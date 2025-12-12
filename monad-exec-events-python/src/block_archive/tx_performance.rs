use monad_event_capture::EventCaptureNextResult;
use monad_exec_events::{ExecEvent, ExecEventDecoder, ExecEventRef};
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::error::PyPolarsErr;

use crate::{
    block_archive::{BlockArchiveScanner, BlockArchiveTask, BlockProcessor},
    create_scanner,
};

create_scanner!(
    BlockArchiveTxPerformanceScanner,
    TxPerformanceScanner,
    TxPerformanceProcessor
);

#[repr(C)]
#[pyclass]
#[derive(Default)]
pub struct TxPerformanceScanner;

impl BlockArchiveScanner for TxPerformanceScanner {
    type BlockProcessor = TxPerformanceBlockProcessor;

    fn schema() -> Schema {
        [
            ("block_number", DataType::UInt64),
            ("tx_index", DataType::UInt32),
            ("start", DataType::Datetime(TimeUnit::Nanoseconds, None)),
            (
                "perf_enter",
                DataType::Datetime(TimeUnit::Nanoseconds, None),
            ),
            ("perf_exit", DataType::Datetime(TimeUnit::Nanoseconds, None)),
            ("end", DataType::Datetime(TimeUnit::Nanoseconds, None)),
        ]
        .into_iter()
        .map(|(name, datatype)| Field::new(PlSmallStr::from_static(name), datatype))
        .collect::<Schema>()
    }

    fn create_processor(&self) -> Self::BlockProcessor
    where
        Self: Sized,
    {
        TxPerformanceBlockProcessor
    }
}

#[repr(C)]
#[pyclass]
pub struct TxPerformanceBlockProcessor;

impl BlockProcessor for TxPerformanceBlockProcessor {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>> {
        let BlockArchiveTask {
            block_number,
            mut reader,
        } = task;

        let event_section: monad_event_capture::EventCaptureEventSection<'_, ExecEventDecoder> =
            reader.next_event_section().unwrap();

        let mut event_iter = event_section.open_iterator();

        let mut tx_index = Vec::default();
        let mut start = Vec::default();
        let mut perf_enter = Vec::default();
        let mut perf_exit = Vec::default();
        let mut end = Vec::default();

        loop {
            match event_iter.next_descriptor() {
                EventCaptureNextResult::End => {
                    break;
                }
                EventCaptureNextResult::NoSeqno => unimplemented!(),
                EventCaptureNextResult::Success(event_descriptor) => {
                    let Some(exec_event) =
                        event_descriptor.try_filter_map(|event_ref| match event_ref {
                            event @ (ExecEventRef::BlockStart(_)
                            | ExecEventRef::TxnHeaderStart { .. }
                            | ExecEventRef::TxnPerfEvmEnter
                            | ExecEventRef::TxnPerfEvmExit
                            | ExecEventRef::TxnEnd
                            | ExecEventRef::RecordError(_)) => Some(event.into_owned()),
                            _ => None,
                        })
                    else {
                        continue;
                    };

                    match exec_event {
                        ExecEvent::BlockStart(block_start) => {
                            assert_eq!(block_number, block_start.eth_block_input.number);
                        }
                        ExecEvent::TxnHeaderStart {
                            txn_index,
                            txn_header_start,
                            data_bytes,
                            blob_bytes,
                        } => {
                            tx_index.push(TryInto::<u32>::try_into(txn_index).unwrap());
                            start.push(event_descriptor.info().record_epoch_nanos);
                        }
                        ExecEvent::TxnPerfEvmEnter => {
                            perf_enter.push(event_descriptor.info().record_epoch_nanos);
                        }
                        ExecEvent::TxnPerfEvmExit => {
                            perf_exit.push(event_descriptor.info().record_epoch_nanos);
                        }
                        ExecEvent::TxnEnd => {
                            end.push(event_descriptor.info().record_epoch_nanos);
                        }
                        ExecEvent::RecordError(err) => {
                            panic!("{err:#?}");
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        let block_number = UInt64Chunked::full(
            PlSmallStr::from_static("block_number"),
            block_number,
            tx_index.len(),
        )
        .into_series();

        let tx_index = Series::new(PlSmallStr::from_static("tx_index"), tx_index);
        let start = Series::new(PlSmallStr::from_static("start"), start);
        let perf_enter = Series::new(PlSmallStr::from_static("perf_enter"), perf_enter);
        let perf_exit = Series::new(PlSmallStr::from_static("perf_exit"), perf_exit);
        let end = Series::new(PlSmallStr::from_static("end"), end);

        let columns = vec![block_number, tx_index, start, perf_enter, perf_exit, end]
            .into_iter()
            .map(Series::into_column)
            .collect::<Vec<_>>();

        DataFrame::new(columns)
            .map(Some)
            .map_err(|err| PyPolarsErr::from(err).into())
    }
}
