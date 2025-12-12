use monad_event_capture::EventCaptureNextResult;
use monad_exec_events::{
    ExecEvent, ExecEventDecoder, ExecEventRef,
    ffi::{monad_c_eth_txn_header, monad_exec_txn_header_start},
};
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::{
    error::PyPolarsErr,
    export::polars_arrow::{
        array::{FixedSizeListArray, UInt8Array, UInt64Array},
        bitmap::BitmapBuilder,
    },
};

use crate::{
    block_archive::{BlockArchiveScanner, BlockArchiveTask, BlockProcessor},
    create_scanner,
};

create_scanner!(
    BlockArchiveTxHeaderScanner,
    TxHeaderScanner,
    TxHeaderProcessor
);

#[repr(C)]
#[pyclass]
#[derive(Default)]
pub struct TxHeaderScanner;

impl BlockArchiveScanner for TxHeaderScanner {
    type BlockProcessor = TxHeaderBlockProcessor;

    fn schema() -> Schema {
        [
            ("block_number", DataType::UInt64),
            ("tx_index", DataType::UInt32),
            ("tx_hash", DataType::Array(Box::new(DataType::UInt8), 32)),
            ("sender", DataType::Array(Box::new(DataType::UInt8), 20)),
            ("tx_type", DataType::UInt8),
            ("chain_id", DataType::UInt64),
            ("nonce", DataType::UInt64),
            ("gas_limit", DataType::UInt64),
            (
                "max_fee_per_gas",
                DataType::Array(Box::new(DataType::UInt64), 4),
            ),
            (
                "max_priority_fee_per_gas",
                DataType::Array(Box::new(DataType::UInt64), 4),
            ),
            ("value", DataType::Array(Box::new(DataType::UInt64), 4)),
            ("to", DataType::Array(Box::new(DataType::UInt8), 20)),
            ("is_contract_creation", DataType::Boolean),
            ("r", DataType::Array(Box::new(DataType::UInt64), 4)),
            ("s", DataType::Array(Box::new(DataType::UInt64), 4)),
            ("y_parity", DataType::Boolean),
            (
                "max_fee_per_blob_gas",
                DataType::Array(Box::new(DataType::UInt64), 4),
            ),
            ("data_length", DataType::UInt32),
            ("blob_versioned_hash_length", DataType::UInt32),
            ("access_list_count", DataType::UInt32),
            ("auth_list_count", DataType::UInt32),
        ]
        .into_iter()
        .map(|(name, datatype)| Field::new(PlSmallStr::from_static(name), datatype))
        .collect::<Schema>()
    }

    fn create_processor(&self) -> Self::BlockProcessor
    where
        Self: Sized,
    {
        TxHeaderBlockProcessor
    }
}

#[repr(C)]
#[pyclass]
pub struct TxHeaderBlockProcessor;

impl BlockProcessor for TxHeaderBlockProcessor {
    fn run(task: BlockArchiveTask) -> PyResult<Option<DataFrame>> {
        let BlockArchiveTask {
            block_number,
            mut reader,
        } = task;

        let event_section: monad_event_capture::EventCaptureEventSection<'_, ExecEventDecoder> =
            reader.next_event_section().unwrap();

        let mut event_iter = event_section.open_iterator();

        let mut col_tx_index = Vec::default();
        let mut col_tx_hash = Vec::default();
        let mut col_sender = Vec::default();
        let mut col_tx_type = Vec::default();
        let mut col_chain_id = Vec::default();
        let mut col_nonce = Vec::default();
        let mut col_gas_limit = Vec::default();
        let mut col_max_fee_per_gas = Vec::default();
        let mut col_max_priority_fee_per_gas = Vec::default();
        let mut col_value = Vec::default();
        let mut col_to = Vec::default();
        let mut col_is_contract_creation = BitmapBuilder::new();
        let mut col_r = Vec::default();
        let mut col_s = Vec::default();
        let mut col_y_parity = BitmapBuilder::new();
        let mut col_max_fee_per_blob_gas = Vec::default();
        let mut col_data_length = Vec::default();
        let mut col_blob_versioned_hash_length = Vec::default();
        let mut col_access_list_count = Vec::default();
        let mut col_auth_list_count = Vec::default();

        loop {
            match event_iter.next_descriptor() {
                EventCaptureNextResult::End => {
                    break;
                }
                EventCaptureNextResult::NoSeqno => unimplemented!(),
                EventCaptureNextResult::Success(event_descriptor) => {
                    let Some(exec_event) =
                        event_descriptor.try_filter_map(|event_ref| match event_ref {
                            event @ (ExecEventRef::TxnHeaderStart { .. }
                            | ExecEventRef::RecordError(_)) => Some(event.into_owned()),
                            _ => None,
                        })
                    else {
                        continue;
                    };

                    match exec_event {
                        ExecEvent::TxnHeaderStart {
                            txn_index,
                            txn_header_start:
                                monad_exec_txn_header_start {
                                    txn_hash,
                                    sender,
                                    txn_header:
                                        monad_c_eth_txn_header {
                                            txn_type,
                                            chain_id,
                                            nonce,
                                            gas_limit,
                                            max_fee_per_gas,
                                            max_priority_fee_per_gas,
                                            value,
                                            to,
                                            is_contract_creation,
                                            r,
                                            s,
                                            y_parity,
                                            max_fee_per_blob_gas,
                                            data_length,
                                            blob_versioned_hash_length,
                                            access_list_count,
                                            auth_list_count,
                                        },
                                },
                            data_bytes,
                            blob_bytes,
                        } => {
                            col_tx_index.push(TryInto::<u32>::try_into(txn_index).unwrap());
                            col_tx_hash.extend(txn_hash.bytes);
                            col_sender.extend(sender.bytes);
                            col_tx_type.push(txn_type);
                            // TODO(andr-dev): Fix this
                            col_chain_id.push(chain_id.limbs[0]);
                            col_nonce.push(nonce);
                            col_gas_limit.push(gas_limit);
                            col_max_fee_per_gas.extend(max_fee_per_gas.limbs);
                            col_max_priority_fee_per_gas.extend(max_priority_fee_per_gas.limbs);
                            col_value.extend(value.limbs);
                            col_to.extend(to.bytes);
                            col_is_contract_creation.push(is_contract_creation);
                            col_r.extend(r.limbs);
                            col_s.extend(s.limbs);
                            col_y_parity.push(y_parity);
                            col_max_fee_per_blob_gas.extend(max_fee_per_blob_gas.limbs);
                            col_data_length.push(data_length);
                            col_blob_versioned_hash_length.push(blob_versioned_hash_length);
                            col_access_list_count.push(access_list_count);
                            col_auth_list_count.push(auth_list_count);
                        }
                        ExecEvent::RecordError(err) => {
                            panic!("{err:#?}");
                        }
                        _ => unreachable!(),
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

        let build_uint256_ne = |name: &'static str, values: Vec<u64>| {
            assert!(values.len() % 4 == 0);

            Series::from_arrow(
                PlSmallStr::from_static(name),
                Box::new(
                    FixedSizeListArray::try_new(
                        ArrowDataType::FixedSizeList(
                            Box::new(ArrowField::new(
                                PlSmallStr::EMPTY,
                                ArrowDataType::UInt64,
                                false,
                            )),
                            4,
                        ),
                        values.len() / 4,
                        UInt64Array::from_vec(values).boxed(),
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
            col_tx_index.len(),
        )
        .into_series();

        let col_tx_index = Series::new(PlSmallStr::from_static("tx_index"), col_tx_index);
        let col_tx_hash = build_fixed("tx_hash", 32, col_tx_hash);
        let col_sender = build_fixed("sender", 20, col_sender);
        let col_tx_type = Series::new(PlSmallStr::from_static("tx_type"), col_tx_type);
        let col_chain_id = Series::new(PlSmallStr::from_static("chain_id"), col_chain_id);
        let col_nonce = Series::new(PlSmallStr::from_static("nonce"), col_nonce);
        let col_gas_limit = Series::new(PlSmallStr::from_static("gas_limit"), col_gas_limit);
        let col_max_fee_per_gas = build_uint256_ne("max_fee_per_gas", col_max_fee_per_gas);
        let col_max_priority_fee_per_gas =
            build_uint256_ne("max_priority_fee_per_gas", col_max_priority_fee_per_gas);
        let col_value = build_uint256_ne("value", col_value);
        let col_to = build_fixed("to", 20, col_to);
        let col_is_contract_creation = BooleanChunked::from_bitmap(
            PlSmallStr::from_static("is_contract_creation"),
            col_is_contract_creation.freeze(),
        )
        .into_series();
        let col_r = build_uint256_ne("r", col_r);
        let col_s = build_uint256_ne("s", col_s);
        let col_y_parity =
            BooleanChunked::from_bitmap(PlSmallStr::from_static("y_parity"), col_y_parity.freeze())
                .into_series();
        let col_max_fee_per_blob_gas =
            build_uint256_ne("max_fee_per_blob_gas", col_max_fee_per_blob_gas);
        let col_data_length = Series::new(PlSmallStr::from_static("data_length"), col_data_length);
        let col_blob_versioned_hash_length = Series::new(
            PlSmallStr::from_static("blob_versioned_hash_length"),
            col_blob_versioned_hash_length,
        );
        let col_access_list_count = Series::new(
            PlSmallStr::from_static("access_list_count"),
            col_access_list_count,
        );
        let col_auth_list_count = Series::new(
            PlSmallStr::from_static("auth_list_count"),
            col_auth_list_count,
        );

        let columns = vec![
            block_number,
            col_tx_index,
            col_tx_hash,
            col_sender,
            col_tx_type,
            col_chain_id,
            col_nonce,
            col_gas_limit,
            col_max_fee_per_gas,
            col_max_priority_fee_per_gas,
            col_value,
            col_to,
            col_is_contract_creation,
            col_r,
            col_s,
            col_y_parity,
            col_max_fee_per_blob_gas,
            col_data_length,
            col_blob_versioned_hash_length,
            col_access_list_count,
            col_auth_list_count,
        ]
        .into_iter()
        .map(Series::into_column)
        .collect::<Vec<_>>();

        DataFrame::new(columns)
            .map(Some)
            .map_err(|err| PyPolarsErr::from(err).into())
    }
}
