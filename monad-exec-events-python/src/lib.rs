use pyo3::prelude::*;

use crate::block_archive::BlockArchive;

mod block_archive;

#[pymodule]
fn monad_exec_events(monad_exec_events: &Bound<PyModule>) -> PyResult<()> {
    monad_exec_events.add_class::<BlockArchive>().unwrap();

    Ok(())
}
