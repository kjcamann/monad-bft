use std::{collections::VecDeque, num::NonZeroUsize, path::PathBuf, thread::JoinHandle};

use monad_block_capture::BlockCaptureBlockArchive;
use monad_event_capture::EventCaptureReader;
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::{PyDataFrame, error::PyPolarsErr};

use self::{
    block_performance::{BlockArchiveBlockPerformanceScanner, BlockPerformanceScanner},
    slot_updates::{BlockArchiveSlotUpdatesScanner, SlotUpdateScanner},
    tx_gas::{BlockArchiveTxGasScanner, TxGasScanner},
    tx_header::{BlockArchiveTxHeaderScanner, TxHeaderScanner},
    tx_performance::{BlockArchiveTxPerformanceScanner, TxPerformanceScanner},
};

mod block_performance;
mod slot_updates;
mod tx_gas;
mod tx_header;
mod tx_performance;

#[repr(C)]
#[pyclass]
pub struct BlockArchive {
    block_archive: Arc<BlockCaptureBlockArchive>,
}

#[pymethods]
impl BlockArchive {
    #[new]
    fn new(path: PathBuf) -> Self {
        let block_archive =
            BlockCaptureBlockArchive::new(&std::fs::File::open(path).unwrap()).unwrap();

        Self {
            block_archive: Arc::new(block_archive),
        }
    }

    fn create_slot_update_scanner(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> BlockArchiveSlotUpdatesScanner {
        BlockArchiveSlotUpdatesScanner {
            block_archive: self.block_archive.clone(),

            start_block,
            end_block,

            scanner: SlotUpdateScanner,
        }
    }

    fn create_block_performance_scanner(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> BlockArchiveBlockPerformanceScanner {
        BlockArchiveBlockPerformanceScanner {
            block_archive: self.block_archive.clone(),

            start_block,
            end_block,

            scanner: BlockPerformanceScanner,
        }
    }

    fn create_tx_performance_scanner(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> BlockArchiveTxPerformanceScanner {
        BlockArchiveTxPerformanceScanner {
            block_archive: self.block_archive.clone(),

            start_block,
            end_block,

            scanner: TxPerformanceScanner,
        }
    }

    fn create_tx_gas_scanner(&self, start_block: u64, end_block: u64) -> BlockArchiveTxGasScanner {
        BlockArchiveTxGasScanner {
            block_archive: self.block_archive.clone(),

            start_block,
            end_block,

            scanner: TxGasScanner,
        }
    }

    fn create_tx_header_scanner(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> BlockArchiveTxHeaderScanner {
        BlockArchiveTxHeaderScanner {
            block_archive: self.block_archive.clone(),

            start_block,
            end_block,

            scanner: TxHeaderScanner,
        }
    }
}

pub trait BlockArchiveScanner {
    type BlockProcessor;

    fn schema() -> Schema;

    fn create_processor(&self) -> Self::BlockProcessor
    where
        Self: Sized;
}

pub trait BlockProcessor: Send + Sync {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>>;
}

#[repr(C)]
pub struct BlockProcessorHarness<P>
where
    P: BlockProcessor,
{
    block_archive: Arc<BlockCaptureBlockArchive>,

    threads: NonZeroUsize,
    tasks: VecDeque<JoinHandle<PyResult<Option<DataFrame>>>>,

    current_block: u64,
    end_block: u64,

    max_rows: Option<usize>,
    predicate: Option<Expr>,
    with_columns: Option<Vec<String>>,

    dataframe: Option<DataFrame>,

    processor: P,
}

impl<P> BlockProcessorHarness<P>
where
    P: BlockProcessor,
{
    fn next(&mut self) -> PyResult<Option<PyDataFrame>> {
        let ret_dataframe = loop {
            while self.current_block <= self.end_block && self.tasks.len() < self.threads.get() {
                let reader = self
                    .block_archive
                    .open_block(self.current_block)
                    .map_err(|err| PyPolarsErr::Other(err.to_string()))?;

                self.tasks.push_back(std::thread::spawn({
                    let block_number = self.current_block;

                    let predicate = self.predicate.clone();
                    let with_columns = self.with_columns.clone();

                    move || {
                        let df: Option<DataFrame> = P::run(BlockArchiveTask {
                            block_number,
                            reader,
                        })?;

                        let Some(mut df) = df else {
                            return Ok(None);
                        };

                        if let Some(predicate) = predicate {
                            df = df
                                .lazy()
                                .filter(predicate)
                                .collect()
                                .map_err(PyPolarsErr::from)?;
                        }

                        if let Some(with_columns) = with_columns {
                            df = df.select(with_columns).map_err(PyPolarsErr::from)?;
                        }

                        Ok(Some(df))
                    }
                }));

                self.current_block += 1;
            }

            let Some(task) = self.tasks.pop_front() else {
                break self.dataframe.take();
            };

            let Some(next_dataframe) = task.join().unwrap()? else {
                continue;
            };

            let max_stack_height = self.max_rows.map(|max_rows| {
                self.dataframe
                    .as_ref()
                    .map(|df| max_rows.saturating_sub(df.height()))
                    .unwrap_or(max_rows)
            });

            let (stack_dataframe, store_dataframe) =
                if let Some(max_stack_height) = max_stack_height {
                    if max_stack_height == 0 {
                        break self.dataframe.replace(next_dataframe);
                    }

                    let (stack_dataframe, store_dataframe) =
                        next_dataframe.split_at(max_stack_height.try_into().unwrap());

                    (stack_dataframe, Some(store_dataframe))
                } else {
                    (next_dataframe, None)
                };

            if let Some(dataframe) = self.dataframe.as_mut() {
                let _ = dataframe
                    .vstack_mut_owned(stack_dataframe)
                    .map_err(PyPolarsErr::from)?;
            } else {
                self.dataframe = Some(stack_dataframe);
            }

            if let Some(store_dataframe) = store_dataframe {
                if self
                    .dataframe
                    .as_ref()
                    .map(|df| df.height())
                    .unwrap_or_default()
                    != 0
                {
                    break self.dataframe.replace(store_dataframe);
                } else {
                    self.dataframe = Some(store_dataframe);
                }
            }
        };

        Ok(ret_dataframe.map(PyDataFrame))
    }
}

#[macro_export]
macro_rules! create_scanner {
    ($name: ident, $type: ident, $processor: ident) => {
        #[pyclass]
        pub struct $name {
            pub(crate) block_archive:
                std::sync::Arc<::monad_block_capture::BlockCaptureBlockArchive>,

            pub(crate) start_block: u64,
            pub(crate) end_block: u64,

            pub(crate) scanner: $type,
        }

        #[pymethods]
        impl $name {
            #[staticmethod]
            pub fn schema() -> pyo3_polars::PySchema {
                pyo3_polars::PySchema(std::sync::Arc::new(
                    <$type as crate::block_archive::BlockArchiveScanner>::schema(),
                ))
            }

            pub fn create_processor(&self) -> $processor {
                let threads = std::thread::available_parallelism()
                    .unwrap_or_else(|_| std::num::NonZero::new(1).unwrap());

                let processor =
                    <$type as crate::block_archive::BlockArchiveScanner>::create_processor(
                        &self.scanner,
                    );

                $processor(crate::block_archive::BlockProcessorHarness {
                    block_archive: self.block_archive.clone(),

                    threads,
                    tasks: std::collections::VecDeque::default(),

                    current_block: self.start_block,
                    end_block: self.end_block,

                    max_rows: None,
                    predicate: None,
                    with_columns: None,

                    dataframe: None,

                    processor,
                })
            }
        }

        #[pyclass]
        pub struct $processor(
            crate::block_archive::BlockProcessorHarness<
                <$type as crate::block_archive::BlockArchiveScanner>::BlockProcessor,
            >,
        );

        #[pymethods]
        impl $processor {
            fn set_max_rows(&mut self, max_rows: u64) {
                self.0.max_rows = Some(max_rows.try_into().unwrap());
            }

            fn set_predicate(&mut self, predicate: ::pyo3_polars::PyExpr) {
                self.0.predicate = Some(predicate.0);
            }

            fn set_with_columns(&mut self, columns: Vec<String>) {
                self.0.with_columns = Some(columns)
            }

            fn next(&mut self) -> ::pyo3::PyResult<Option<::pyo3_polars::PyDataFrame>> {
                self.0.next()
            }
        }
    };
}

pub struct BlockArchiveTask {
    block_number: u64,
    reader: EventCaptureReader,
}
