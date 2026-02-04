pub use block_archive::{BlockArchive, BlockArchiveScanner, BlockProcessorHarness};
use pyo3::prelude::*;

mod block_archive;

#[pymodule]
fn monad_exec_events(monad_exec_events: &Bound<PyModule>) -> PyResult<()> {
    monad_exec_events.add_class::<BlockArchive>().unwrap();

    Ok(())
}
