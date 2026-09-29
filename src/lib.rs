use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
mod processor {
    use pyo3::prelude::*;

    /// Formats the sum of two numbers as string.
    #[pyfunction]
    fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
        let result = a + b;
        Ok(format!("JP sum: {}", result))
        // Ok((a + b).to_string())
    }

    #[pyfunction]
    fn process_bytes(mut pkt: Vec<u8>) -> PyResult<Vec<u8>> {
        if pkt.len() >= 3 {
            pkt[1] = 0xff
        }

        Ok(pkt)
    }
}
