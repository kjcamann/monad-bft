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
    BlockArchiveBlockPerformanceScanner,
    BlockPerformanceScanner,
    BlockPerformanceProcessor
);

#[repr(C)]
#[pyclass]
#[derive(Default)]
pub struct BlockPerformanceScanner;

impl BlockArchiveScanner for BlockPerformanceScanner {
    type BlockProcessor = BlockPerformanceBlockProcessor;

    fn schema() -> Schema {
        [
            ("block_number", DataType::UInt64),
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
        BlockPerformanceBlockProcessor
    }
}

#[repr(C)]
#[pyclass]
pub struct BlockPerformanceBlockProcessor;

impl BlockProcessor for BlockPerformanceBlockProcessor {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>> {
        let BlockArchiveTask {
            block_number,
            mut reader,
        } = task;

        let event_section: monad_event_capture::EventCaptureEventSection<'_, ExecEventDecoder> =
            reader.next_event_section().unwrap();

        let mut event_iter = event_section.open_iterator();

        let mut start = None;
        let mut perf_enter = None;
        let mut perf_exit = None;
        let mut end = None;

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
                            | ExecEventRef::BlockPerfEvmEnter
                            | ExecEventRef::BlockPerfEvmExit
                            | ExecEventRef::BlockEnd(_)
                            | ExecEventRef::RecordError(_)) => Some(event.into_owned()),
                            _ => None,
                        })
                    else {
                        continue;
                    };

                    match exec_event {
                        ExecEvent::BlockStart(block_start) => {
                            assert_eq!(block_number, block_start.eth_block_input.number);

                            assert!(
                                start
                                    .replace(event_descriptor.info().record_epoch_nanos)
                                    .is_none()
                            );
                        }
                        ExecEvent::BlockPerfEvmEnter => {
                            assert!(
                                perf_enter
                                    .replace(event_descriptor.info().record_epoch_nanos)
                                    .is_none()
                            );
                        }
                        ExecEvent::BlockPerfEvmExit => {
                            assert!(
                                perf_exit
                                    .replace(event_descriptor.info().record_epoch_nanos)
                                    .is_none()
                            );
                        }
                        ExecEvent::BlockEnd(_) => {
                            assert!(
                                end.replace(event_descriptor.info().record_epoch_nanos)
                                    .is_none()
                            );
                        }
                        ExecEvent::RecordError(err) => {
                            panic!("{err:#?}");
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }

        let block_number =
            UInt64Chunked::full(PlSmallStr::from_static("block_number"), block_number, 1)
                .into_series();

        let start = Series::new(PlSmallStr::from_static("start"), vec![start]);
        let perf_enter = Series::new(PlSmallStr::from_static("perf_enter"), vec![perf_enter]);
        let perf_exit = Series::new(PlSmallStr::from_static("perf_exit"), vec![perf_exit]);
        let end = Series::new(PlSmallStr::from_static("end"), vec![end]);

        let columns = vec![block_number, start, perf_enter, perf_exit, end]
            .into_iter()
            .map(Series::into_column)
            .collect::<Vec<_>>();

        DataFrame::new(columns)
            .map(Some)
            .map_err(|err| PyPolarsErr::from(err).into())
    }
}
