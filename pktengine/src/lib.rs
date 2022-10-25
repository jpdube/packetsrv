use pyo3::prelude::*;
// use pyo3::{prelude::*, types::PyType};

pub mod packetref;

use byteorder::{BigEndian, ByteOrder};
use packetref::PacketRef;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
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
fn pktengine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(fast_packet_search, m)?)?;
    Ok(())
}
