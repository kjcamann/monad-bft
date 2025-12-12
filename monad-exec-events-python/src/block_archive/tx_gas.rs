use monad_event_capture::EventCaptureNextResult;
use monad_exec_events::{ExecEventDecoder, ExecutedBlockBuilder};
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::{
    error::PyPolarsErr,
    export::polars_arrow::array::{FixedSizeListArray, UInt8Array},
};

use crate::{
    block_archive::{BlockArchiveScanner, BlockArchiveTask, BlockProcessor},
    create_scanner,
};

create_scanner!(BlockArchiveTxGasScanner, TxGasScanner, TxGasProcessor);

#[repr(C)]
#[pyclass]
#[derive(Default)]
pub struct TxGasScanner;

impl BlockArchiveScanner for TxGasScanner {
    type BlockProcessor = TxGasBlockProcessor;

    fn schema() -> Schema {
        [
            ("block_number", DataType::UInt64),
            ("tx_index", DataType::UInt32),
            ("tx_hash", DataType::Array(Box::new(DataType::UInt8), 32)),
            ("status", DataType::Int32),
            ("gas_used", DataType::UInt64),
            ("gas_used_vm", DataType::UInt64),
            ("gas_limit", DataType::UInt64),
            ("gas_limit_vm", DataType::UInt64),
        ]
        .into_iter()
        .map(|(name, datatype)| Field::new(PlSmallStr::from_static(name), datatype))
        .collect::<Schema>()
    }

    fn create_processor(&self) -> Self::BlockProcessor
    where
        Self: Sized,
    {
        TxGasBlockProcessor
    }
}

#[repr(C)]
#[pyclass]
pub struct TxGasBlockProcessor;

impl BlockProcessor for TxGasBlockProcessor {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>> {
        let BlockArchiveTask {
            block_number,
            mut reader,
        } = task;

        let event_section: monad_event_capture::EventCaptureEventSection<'_, ExecEventDecoder> =
            reader.next_event_section().unwrap();

        let mut event_iter = event_section.open_iterator();

        let mut block_builder = ExecutedBlockBuilder::new(true, false);

        let block = loop {
            match event_iter.next_descriptor() {
                EventCaptureNextResult::End => {
                    unreachable!()
                }
                EventCaptureNextResult::NoSeqno => unimplemented!(),
                EventCaptureNextResult::Success(event_descriptor) => {
                    match block_builder.process_event_descriptor(&event_descriptor) {
                        None => continue,
                        Some(result) => break result.unwrap(),
                    }
                }
            }
        };

        let mut tx_index = Vec::default();
        let mut tx_hash = Vec::default();
        let mut status = Vec::default();
        let mut gas_used = Vec::default();
        let mut gas_used_vm = Vec::default();
        let mut gas_limit = Vec::default();
        let mut gas_limit_vm = Vec::default();

        for (index, tx) in block.txns.into_iter().enumerate() {
            tx_index.push(TryInto::<u32>::try_into(index).unwrap());

            tx_hash.extend(tx.hash.bytes);

            let tx_call_frames = tx.call_frames.unwrap();

            let call_frame = tx_call_frames.get(0).unwrap().call_frame;

            status.push(call_frame.evmc_status);

            gas_used.push(tx.receipt.gas_used);

            gas_used_vm.push(call_frame.gas_used);

            gas_limit.push(tx.header.gas_limit);

            gas_limit_vm.push(call_frame.gas);
        }

        let build_fixed = |name: &'static str, width: usize, values: Vec<u8>| {
            assert!(values.len() % width == 0);

            Series::from_arrow(
                PlSmallStr::from_static(name),
                Box::new(
                    FixedSizeListArray::try_new(
                        ArrowDataType::FixedSizeList(
                            Box::new(ArrowField::new(
                                PlSmallStr::EMPTY,
                                ArrowDataType::UInt8,
                                false,
                            )),
                            width,
                        ),
                        values.len() / width,
                        UInt8Array::from_vec(values).boxed(),
                        None,
                    )
                    .unwrap(),
                ),
            )
            .unwrap()
        };

        let block_number = UInt64Chunked::full(
            PlSmallStr::from_static("block_number"),
            block_number,
            tx_index.len(),
        )
        .into_series();

        let tx_index = Series::new(PlSmallStr::from_static("tx_index"), tx_index);
        let tx_hash = build_fixed("tx_hash", 32, tx_hash);
        let status = Series::new(PlSmallStr::from_static("status"), status);
        let gas_used = Series::new(PlSmallStr::from_static("gas_used"), gas_used);
        let gas_used_vm = Series::new(PlSmallStr::from_static("gas_used_vm"), gas_used_vm);
        let gas_limit = Series::new(PlSmallStr::from_static("gas_limit"), gas_limit);
        let gas_limit_vm = Series::new(PlSmallStr::from_static("gas_limit_vm"), gas_limit_vm);

        let columns = vec![
            block_number,
            tx_index,
            tx_hash,
            status,
            gas_used,
            gas_used_vm,
            gas_limit,
            gas_limit_vm,
        ]
        .into_iter()
        .map(Series::into_column)
        .collect::<Vec<_>>();

        DataFrame::new(columns)
            .map(Some)
            .map_err(|err| PyPolarsErr::from(err).into())
    }
}
