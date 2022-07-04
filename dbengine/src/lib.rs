use pyo3::{prelude::*, types::PyType};
use rusqlite::{params, Connection, Result};

const DB_FILENAME: &str = "/Users/jpdube/hull-voip/db/index.db";

#[pyclass]
#[derive(Default)]
pub struct DbEngine {
    #[pyo3(get, set)]
    filename: String,

    #[pyo3(get)]
    query_cache: Vec<String>,
}

#[pymethods]
impl DbEngine {
    #[new]
    pub fn new() -> Self {
        Self {
            filename: "path/db/packet.db".to_owned(),
            query_cache: Vec::new(),
        }
    }

    pub fn dbname(&self) -> PyResult<String> {
        return Ok(self.filename.clone());
    }
}

#[pyclass]
pub struct Index {
    #[pyo3(get, set)]
    dbname: String,
    conn: Connection,
}

#[pymethods]
impl Index {
    #[new]
    fn new() -> Self {
        Index {
            dbname: DB_FILENAME.to_string(),
            conn: Connection::open_in_memory().unwrap(),
        }
    }

    pub fn init(&mut self) {
        self.conn
            .execute(
                "create table if not exists packet(
            id integer,
            ip_src integer,
            ip_dst integer,
            mac_src integer,
            mac_dst integer,
            ether_type integer,
            ip_proto integer,
            vlan_id integer,
            sport integer,
            dport integer,
            file_ptr integer,
            file_id integer,
            timestamp timestamp,
            UNIQUE(id))",
                [],
            )
            .unwrap();

        _ = self
            .conn
            .execute(&format!("attach '{}' as A;", DB_FILENAME), []);
    }

    // #[classmethod]
    pub fn save(&mut self, sql: String) -> PyResult<bool> {
        let sql_index = sql.replace("packet", "A.packet");
        println!("{}", sql_index);
        self.conn
            .execute(&format!("insert or ignore into packet {}", sql_index), [])
            .unwrap();
        Ok(true)
    }

    pub fn count(&self) -> PyResult<usize> {
        let mut count: usize = 22;
        let mut stmt = self.conn.prepare("select count(1) from packet;").unwrap();
        let _ = stmt.query_map([], |row| Ok(count = row.get(0)?)).unwrap();

        Ok(count)
    }
}

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[pyfunction]
fn array_test() -> PyResult<Vec<u8>> {
    Ok(vec![0, 1, 2, 3])
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn dbengine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(array_test, m)?)?;
    m.add_class::<DbEngine>()?;
    m.add_class::<Index>()?;

    Ok(())
}
