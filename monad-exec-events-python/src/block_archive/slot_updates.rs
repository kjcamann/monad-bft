use std::collections::BTreeMap;

use itertools::Either;
use monad_event_capture::EventCaptureNextResult;
use monad_exec_events::{ExecEventDecoder, ExecEventRef, ffi::monad_exec_account_access};
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::{
    error::PyPolarsErr,
    export::polars_arrow::{
        array::{FixedSizeListArray, UInt8Array},
        bitmap::BitmapBuilder,
    },
};

use crate::{
    block_archive::{BlockArchiveScanner, BlockArchiveTask, BlockProcessor},
    create_scanner,
};

create_scanner!(
    BlockArchiveSlotUpdatesScanner,
    SlotUpdateScanner,
    SlotUpdateProcessor
);

#[repr(C)]
#[pyclass]
#[derive(Default)]
pub struct SlotUpdateScanner;

impl BlockArchiveScanner for SlotUpdateScanner {
    type BlockProcessor = SlotUpdateBlockProcessor;

    fn schema() -> Schema {
        [
            ("block_number", DataType::UInt64),
            ("tx_index", DataType::UInt32),
            ("address", DataType::Array(Box::new(DataType::UInt8), 20)),
            ("transient", DataType::Boolean),
            ("slot", DataType::Array(Box::new(DataType::UInt8), 32)),
            (
                "value_before",
                DataType::Array(Box::new(DataType::UInt8), 32),
            ),
            ("modified", DataType::Boolean),
            (
                "value_after",
                DataType::Array(Box::new(DataType::UInt8), 32),
            ),
        ]
        .into_iter()
        .map(|(name, datatype)| Field::new(PlSmallStr::from_static(name), datatype))
        .collect::<Schema>()
    }

    fn create_processor(&self) -> Self::BlockProcessor
    where
        Self: Sized,
    {
        SlotUpdateBlockProcessor
    }
}

#[repr(C)]
#[pyclass]
pub struct SlotUpdateBlockProcessor;

impl BlockProcessor for SlotUpdateBlockProcessor {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>> {
        let BlockArchiveTask {
            block_number,
            mut reader,
        } = task;

        let event_section: monad_event_capture::EventCaptureEventSection<'_, ExecEventDecoder> =
            reader.next_event_section().unwrap();

        let mut event_iter = event_section.open_iterator();

        let mut account_accesses = BTreeMap::<usize, Vec<monad_exec_account_access>>::default();

        let mut tx_index = Vec::default();
        let mut address = Vec::default();
        let mut transient = Vec::default();
        let mut slot = Vec::default();
        let mut value_before = Vec::default();
        let mut modified = BitmapBuilder::new();
        let mut value_after = Vec::default();

        loop {
            match event_iter.next_descriptor() {
                EventCaptureNextResult::End => {
                    break;
                }
                EventCaptureNextResult::NoSeqno => unimplemented!(),
                EventCaptureNextResult::Success(event_descriptor) => {
                    let result = event_descriptor.try_filter_map(|event| match event {
                        ExecEventRef::AccountAccess {
                            txn_index,
                            account_access,
                        } => txn_index.map(|txn_index| Either::Left((txn_index, *account_access))),
                        ExecEventRef::StorageAccess {
                            txn_index,
                            account_index,
                            storage_access,
                        } => txn_index.map(|txn_index| {
                            Either::Right((txn_index, account_index, *storage_access))
                        }),
                        ExecEventRef::EvmError(evm_error) => {
                            panic!("{evm_error:#?}")
                        }
                        _ => None,
                    });

                    match result {
                        None => continue,
                        Some(Either::Left((txn_index, account_access))) => {
                            let account_accesses = account_accesses.entry(txn_index).or_default();

                            assert_eq!(account_accesses.len(), account_access.index as usize);

                            account_accesses.push(account_access);
                        }
                        Some(Either::Right((txn_index, account_index, storage_access))) => {
                            let account_access = account_accesses
                                .get(&txn_index)
                                .unwrap()
                                .get(account_index as usize)
                                .unwrap();

                            tx_index.push(txn_index as u32);
                            address.extend(account_access.address.bytes);
                            transient.push(storage_access.transient);
                            slot.extend(storage_access.key.bytes);
                            value_before.extend(storage_access.start_value.bytes);
                            modified.push(storage_access.modified);
                            value_after.extend(storage_access.end_value.bytes);
                        }
                    }
                }
            }
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
        let address = build_fixed("address", 20, address);
        let transient = Series::new(PlSmallStr::from_static("transient"), transient);
        let slot = build_fixed("slot", 32, slot);
        let value_before = build_fixed("value_before", 32, value_before);

        let modified =
            BooleanChunked::from_bitmap(PlSmallStr::from_static("modified"), modified.freeze())
                .into_series();

        let value_after = build_fixed("value_after", 32, value_after);

        let columns = vec![
            block_number,
            tx_index,
            address,
            transient,
            slot,
            value_before,
            modified,
            value_after,
        ]
        .into_iter()
        .map(Series::into_column)
        .collect::<Vec<_>>();

        DataFrame::new(columns)
            .map(Some)
            .map_err(|err| PyPolarsErr::from(err).into())
    }
}
