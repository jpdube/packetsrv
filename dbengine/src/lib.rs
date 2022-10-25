use pyo3::{prelude::*, types::PyType};
// use rusqlite::{params, Connection, Result};

// const DB_FILENAME: &str = "/Users/jpdube/hull-voip/db/index.db";

// #[pyclass]
// #[derive(Default)]
// pub struct DbEngine {
//     #[pyo3(get, set)]
//     filename: String,

//     #[pyo3(get)]
//     query_cache: Vec<String>,
// }

// #[pymethods]
// impl DbEngine {
//     #[new]
//     pub fn new() -> Self {
//         Self {
//             filename: "path/db/packet.db".to_owned(),
//             query_cache: Vec::new(),
//         }
//     }

//     pub fn dbname(&self) -> PyResult<String> {
//         return Ok(self.filename.clone());
//     }
// }

// #[pyclass]
// pub struct Index {
//     #[pyo3(get, set)]
//     dbname: String,
//     conn: Connection,
// }

// #[pymethods]
// impl Index {
//     #[new]
//     fn new() -> Self {
//         Index {
//             dbname: DB_FILENAME.to_string(),
//             conn: Connection::open_in_memory().unwrap(),
//         }
//     }

//     pub fn init(&mut self) {
//         self.conn
//             .execute(
//                 "create table if not exists packet(
//             id integer,
//             ip_src integer,
//             ip_dst integer,
//             mac_src integer,
//             mac_dst integer,
//             ether_type integer,
//             ip_proto integer,
//             vlan_id integer,
//             sport integer,
//             dport integer,
//             file_ptr integer,
//             file_id integer,
//             timestamp timestamp,
//             UNIQUE(id))",
//                 [],
//             )
//             .unwrap();

//         _ = self
//             .conn
//             .execute(&format!("attach '{}' as A;", DB_FILENAME), []);
//     }

//     // #[classmethod]
//     pub fn save(&mut self, sql: String) -> PyResult<bool> {
//         let sql_index = sql.replace("packet", "A.packet");
//         println!("{}", sql_index);
//         self.conn
//             .execute(&format!("insert or ignore into packet {}", sql_index), [])
//             .unwrap();
//         Ok(true)
//     }

//     pub fn count(&self) -> PyResult<usize> {
//         let mut count: usize = 22;
//         let mut stmt = self.conn.prepare("select count(1) from packet;").unwrap();
//         let _ = stmt.query_map([], |row| Ok(count = row.get(0)?)).unwrap();

//         Ok(count)
//     }
// }

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[pyfunction]
fn array_test() -> PyResult<Vec<u8>> {
    Ok(vec![0, 1, 2, 3])
}
pub mod packetref;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use packetref::PacketRef;
use rayon::prelude::*;
use std::fs::File;
// use std::io::prelude::*;
use std::io::Read;
// use std::thread;
use std::env;
use std::time::SystemTime;

const PCAP_PATH: &str = "/Users/jpdube/hull-voip/db/pcap";

#[pyfunction]
fn search_packet(pcap_file: usize) -> Result<usize, std::io::Error> {
    println!("{}/{}.pcap", PCAP_PATH, pcap_file);
    let mut file = File::open(format!("{}/{}.pcap", PCAP_PATH, pcap_file)).unwrap();
    let mut buffer = [0; 24];
    let mut data = Vec::new();

    let mut psize: usize;
    let mut read_size: usize;
    let mut _packet_count: usize = 0;
    let mut pkt_ptr: usize = 0;
    let mut timestamp: u32;

    file.by_ref().take(24).read(&mut buffer).unwrap();

    loop {
        read_size = file.by_ref().take(16).read(&mut buffer).unwrap();
        if read_size != 16 {
            break;
        }

        pkt_ptr += 16;

        timestamp = BigEndian::read_u32(&buffer[0..4]);
        psize = BigEndian::read_u32(&buffer[12..16]) as usize;
        data.resize(psize, 0);
        file.read_exact(&mut data).unwrap();
        pkt_ptr += psize;

        let mut pkt = PacketRef::new(0, 0, timestamp, 0, pkt_ptr, pcap_file);
        pkt.set_packet(&data);
        _packet_count += 1;
    }

    // println!("Saved {} packets", _packet_count);
    Ok(_packet_count)
}

#[pyfunction]
fn fast_packet_search(file_count: usize) {
    let t_init = SystemTime::now();
    // (0..1).into_par_iter().for_each(move |i| {
    //     search_packet(i).unwrap();
    // });

    let pkt_count: usize = (0..file_count)
        .into_par_iter()
        .map(|pkt| search_packet(pkt).unwrap())
        .sum();

    println!(
        "DB Execution time: {}ms Packets per sec: {:8.0} Total packets: {}",
        t_init.elapsed().unwrap().as_millis(),
        pkt_count as f64 / t_init.elapsed().unwrap().as_secs_f64(),
        pkt_count
    );

    println!("Execution terminated");
}

#[pymodule]
fn dbengine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(fast_packet_search, m)?)?;
    Ok(())
}
