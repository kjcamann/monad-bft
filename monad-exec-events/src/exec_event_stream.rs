//! Module which translates "raw" events in shared memory (which follow the
//! strict, C compatible binary layout rules in `exec_event_ctypes.rs`) into
//! the more ergonomic Rust API types from the `exec_events.rs` module.

use alloy_consensus::TxEip4844Variant;
use alloy_eips::{eip2930, eip7702};
use alloy_primitives::{Bytes, TxKind, B256, B64, U256};
use monad_event_ring::{
    event_reader::{self, EventReader},
    event_ring::monad_event_descriptor,
    event_ring_util::ProcessExitMonitor,
};

use crate::{
    eth_ctypes,
    exec_event_ctypes::{self, exec_event_type, flow_type},
    exec_events::*,
};

/// Result of polling the execution event stream
#[derive(Clone, Debug)]
pub enum PollResult {
    /// No execution event is ready yet
    NotReady,

    /// The execution daemon process is disconnected; this error state is not
    /// recoverable (a new ExecEventStream must be created)
    Disconnected,

    /// Indicates that low-level events were lost in the event ring layer
    /// because events were consumed too slowly. The immediate cause is that
    /// an event sequence number gap occurred (see the `event.md` documentation
    /// for details). When this happens, the event stream has already corrected
    /// the error by skipping over the missing events. This error is returned
    /// to inform the caller that events were lost.
    Gap {
        last_read_seqno: u64,
        last_write_seqno: u64,
    },

    /// Payload memory was overwritten; similar in effect to Gap, but with
    /// different metadata explaining what went wrong
    PayloadExpired {
        expired_seqno: u64,
        last_write_seqno: u64,
        payload_offset: u64,
        buffer_window_start: u64,
    },

    /// A new execution event occurred
    Ready { seqno: u64, event: ExecEvent },
}

// This must be greater than or equal to the maximum consensus execution delay
const FINALIZED_BUFFER_LENGTH: usize = 8;

/// Object which iterates through low-level (C layout compatible) execution
/// events in shared memory, and builds the more ergonomic Rust API type
/// `ExecEvent` to represent them
pub struct ExecEventStream<'ring> {
    reader: EventReader<'ring>,
    config: ExecEventStreamConfig,
    not_ready_polls: u64,
    finalized_buffer: [Option<BlockTag>; FINALIZED_BUFFER_LENGTH],
    finalized_count: usize,
    sink_error: Option<PollResult>,
}

pub struct ExecEventStreamConfig {
    /// If false, the transaction's input is ignored (not made part of the
    /// event); specifically, the alloy_consensus::TxEnvelop field within the
    /// ExecEvent::TransactionStart variant will always be `Bytes::new()`
    pub parse_txn_input: bool,

    /// Optional object used to detect the termination of the execution
    /// daemon; if None, PollResult::Disconnected will not be returned
    pub opt_process_exit_monitor: Option<ProcessExitMonitor>,
}

impl<'ring> ExecEventStream<'ring> {
    pub fn new(
        reader: EventReader<'ring>,
        config: ExecEventStreamConfig,
    ) -> ExecEventStream<'ring> {
        const NONE_INIT: Option<BlockTag> = None;
        ExecEventStream {
            reader,
            config,
            finalized_buffer: [NONE_INIT; FINALIZED_BUFFER_LENGTH],
            finalized_count: 0,
            not_ready_polls: 0,
            sink_error: None,
        }
    }

    /// A non-blocking call which checks if any execution events are ready;
    /// if so, the first available event is consumed and returned
    pub fn poll(&'_ mut self) -> PollResult {
        if let Some(ref x) = self.sink_error {
            return x.clone();
        }
        match self.reader.poll() {
            event_reader::PollResult::NotReady => {
                self.not_ready_polls += 1;
                if self.not_ready_polls & ((1 << 20) - 1) == 0
                    && self.config.opt_process_exit_monitor.is_some()
                    && self
                        .config
                        .opt_process_exit_monitor
                        .as_ref()
                        .unwrap()
                        .has_exited()
                {
                    self.sink_error.replace(PollResult::Disconnected);
                    self.sink_error.as_ref().unwrap().clone()
                } else {
                    PollResult::NotReady
                }
            }
            event_reader::PollResult::Gap {
                last_read_seqno,
                last_write_seqno: _,
            } => {
                self.not_ready_polls = 0;
                self.clear_finalized_buffer();
                // Reset the reader and report the gap
                PollResult::Gap {
                    last_read_seqno,
                    last_write_seqno: self.reader.reset(),
                }
            }
            event_reader::PollResult::Ready(event) => {
                self.not_ready_polls = 0;
                self.create_exec_event(event)
            }
        }
    }

    pub fn reader(&self) -> &EventReader<'ring> {
        &self.reader
    }

    fn create_exec_event(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        use crate::exec_event_ctypes::exec_event_type::*;
        let event_type = unsafe { std::mem::transmute::<u16, exec_event_type>(event.event_type) };
        match event_type {
            RECORD_ERROR => self.act_on_record_error(event),
            BLOCK_START => self.act_on_block_start(event),
            BLOCK_REJECT => self.act_on_block_reject(event),
            BLOCK_PERF_EVM_ENTER => self.act_on_block_perf_evm_enter(event),
            BLOCK_PERF_EVM_EXIT => self.act_on_block_perf_evm_exit(event),
            BLOCK_END => self.act_on_block_end(event),
            BLOCK_QC | BLOCK_FINALIZED => self.act_on_consensus_change(event, event_type),
            BLOCK_VERIFIED => self.act_on_block_verified(event),
            TXN_HEADER_START => self.act_on_txn_header_start(event),
            TXN_ACCESS_LIST_ENTRY => self.act_on_txn_access_list_entry(event),
            TXN_AUTH_LIST_ENTRY => self.act_on_txn_auth_list_entry(event),
            TXN_HEADER_END => self.act_on_txn_header_end(event),
            TXN_REJECT => self.act_on_txn_reject(event),
            TXN_PERF_EVM_ENTER => self.act_on_txn_perf_evm_enter(event),
            TXN_PERF_EVM_EXIT => self.act_on_txn_perf_evm_exit(event),
            TXN_EVM_OUTPUT => self.act_on_txn_evm_output(event),
            TXN_LOG => self.act_on_txn_log(event),
            TXN_CALL_FRAME => self.act_on_txn_call_frame(event),
            TXN_END => self.act_on_txn_end(event),
            ACCOUNT_ACCESS_LIST_HEADER => self.act_on_account_access_header(event),
            ACCOUNT_ACCESS => self.act_on_account_access(event),
            STORAGE_ACCESS => self.act_on_storage_access(event),
            EVM_ERROR => self.act_on_evm_error(event),
            _ => PollResult::NotReady,
        }
    }

    fn act_on_record_error(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        const RECORD_ERROR_SIZE: usize = size_of::<exec_event_ctypes::record_error>();
        let payload = self.reader.payload_peek(&event);
        let record_error =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::record_error) };
        let truncated_end = RECORD_ERROR_SIZE + record_error.truncated_payload_size as usize;
        let truncated_payload = Bytes::copy_from_slice(&payload[RECORD_ERROR_SIZE..truncated_end]);
        self.try_create_event(
            event,
            ExecEvent::RecordError {
                error_type: record_error.error_type,
                dropped_event_type: record_error.dropped_event_type,
                requested_payload_size: record_error.requested_payload_size as usize,
                truncated_payload,
            },
        )
    }

    fn act_on_block_start(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let block_start = unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::block_start) };
        let extra_data = &block_start.eth_block_input.extra_data.as_slice()
            [..block_start.eth_block_input.extra_data_length as usize];
        self.try_create_event(
            event,
            ExecEvent::BlockStart {
                consensus_state: ConsensusState::Proposed,
                block_tag: create_block_tag(&block_start.block_tag),
                chain_id: block_start.chain_id.to::<u64>(),
                eth_block_input: EthBlockInput {
                    parent_hash: block_start.parent_eth_hash,
                    ommers_hash: block_start.eth_block_input.ommers_hash,
                    beneficiary: block_start.eth_block_input.beneficiary,
                    transactions_root: block_start.eth_block_input.transactions_root,
                    difficulty: block_start.eth_block_input.difficulty,
                    number: block_start.eth_block_input.number,
                    gas_limit: block_start.eth_block_input.gas_limit,
                    timestamp: block_start.eth_block_input.timestamp,
                    extra_data: Bytes::copy_from_slice(extra_data),
                    prev_randao: block_start.eth_block_input.prev_randao,
                    nonce: B64::new(block_start.eth_block_input.nonce),
                    base_fee_per_gas: match block_start.eth_block_input.base_fee_per_gas {
                        U256::ZERO => None,
                        f => Some(f),
                    },
                    withdrawals_root: match block_start.eth_block_input.withdrawals_root {
                        B256::ZERO => None,
                        r => Some(r),
                    },
                    transaction_count: block_start.eth_block_input.txn_count,
                },
            },
        )
    }

    fn act_on_block_reject(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let reject_code: u32 =
            unsafe { *(payload.as_ptr() as *const exec_event_ctypes::block_reject) };
        self.try_create_event(event, ExecEvent::BlockReject { reject_code })
    }

    fn act_on_block_perf_evm_enter(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::BlockPerfEvmEnter,
        }
    }

    fn act_on_block_perf_evm_exit(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::BlockPerfEvmExit,
        }
    }

    fn act_on_block_end(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let block_end = unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::block_end) };
        self.try_create_event(
            event,
            ExecEvent::BlockEnd {
                eth_block_hash: block_end.eth_block_hash,
                state_root: block_end.exec_output.state_root,
                receipts_root: block_end.exec_output.receipts_root,
                logs_bloom: Box::new(alloy_primitives::Bloom::from(
                    block_end.exec_output.logs_bloom,
                )),
                gas_used: block_end.exec_output.gas_used,
            },
        )
    }

    fn act_on_block_verified(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let block_number: u64 =
            unsafe { *(payload.as_ptr() as *const exec_event_ctypes::block_verified) }.block_number;
        if let Some(opt_tag) = self.finalized_buffer.iter().find(|opt_tag| {
            opt_tag
                .as_ref()
                .is_some_and(|tag| tag.block_number == block_number)
        }) {
            self.try_create_event(
                event,
                ExecEvent::Referendum {
                    block_tag: *opt_tag.as_ref().unwrap(),
                    outcome: ConsensusState::Verified,
                },
            )
        } else {
            PollResult::NotReady
        }
    }

    fn act_on_consensus_change(
        &'_ mut self,
        event: monad_event_descriptor,
        event_type: exec_event_type,
    ) -> PollResult {
        use crate::exec_event_ctypes::exec_event_type::{BLOCK_FINALIZED, BLOCK_QC};
        let payload = self.reader.payload_peek(&event);
        let block_tag = unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::block_tag) };
        let poll_result = self.try_create_event(
            event,
            ExecEvent::Referendum {
                block_tag: create_block_tag(block_tag),
                outcome: match event_type {
                    BLOCK_QC => ConsensusState::QC,
                    BLOCK_FINALIZED => ConsensusState::Finalized,
                    _ => panic!("{event_type:?} unexpected"),
                },
            },
        );
        if let PollResult::Ready {
            seqno: _,
            event:
                ExecEvent::Referendum {
                    block_tag,
                    outcome: _,
                },
        } = &poll_result
        {
            if event.event_type == BLOCK_FINALIZED as u16 {
                self.finalized_buffer[self.finalized_count % FINALIZED_BUFFER_LENGTH]
                    .replace(*block_tag);
                self.finalized_count += 1;
            }
        };
        poll_result
    }

    fn act_on_txn_header_start(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        const TXN_HEADER_START_SIZE: usize = size_of::<exec_event_ctypes::txn_header_start>();
        let payload = self.reader.payload_peek(&event);
        let txn_no = event.content_ext[flow_type::TXN_ID as usize] - 1;
        let txn_header_start =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_header_start) };
        let input_end = TXN_HEADER_START_SIZE + txn_header_start.txn_header.data_length as usize;
        let input = if self.config.parse_txn_input {
            Bytes::copy_from_slice(&payload[TXN_HEADER_START_SIZE..input_end])
        } else {
            Bytes::new()
        };
        let blob_hashes: &[B256] = unsafe {
            let blob_hashes_base = payload.as_ptr().wrapping_add(input_end) as *const B256;
            std::slice::from_raw_parts(
                blob_hashes_base,
                txn_header_start.txn_header.blob_versioned_hash_length as usize,
            )
        };
        self.try_create_event(
            event,
            ExecEvent::TransactionHeaderStart {
                txn_index: txn_no,
                sender: txn_header_start.sender,
                txn_envelope: create_alloy_tx_envelope(
                    &txn_header_start.txn_hash,
                    &txn_header_start.txn_header,
                    input,
                    blob_hashes.to_vec(),
                ),
                access_list_entry_count: txn_header_start.txn_header.access_list_count,
                authorization_list_entry_count: txn_header_start.txn_header.auth_list_count,
            },
        )
    }

    fn act_on_txn_access_list_entry(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        const LIST_ENTRY_HEADER_SIZE: usize = size_of::<exec_event_ctypes::txn_access_list_entry>();
        let payload = self.reader.payload_peek(&event);
        let list_entry =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_access_list_entry) };
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        let storage_keys: &[B256] = unsafe {
            let topic_base = payload.as_ptr().wrapping_add(LIST_ENTRY_HEADER_SIZE) as *const B256;
            std::slice::from_raw_parts(topic_base, list_entry.entry.storage_key_count as usize)
        };
        self.try_create_event(
            event,
            ExecEvent::TransactionAccessListEntry {
                txn_index,
                access_list_index: list_entry.index,
                entry: eip2930::AccessListItem {
                    address: list_entry.entry.address,
                    storage_keys: storage_keys.to_vec(),
                },
            },
        )
    }

    fn act_on_txn_auth_list_entry(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let list_entry =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_auth_list_entry) };
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;

        let authorization = eip7702::Authorization {
            chain_id: list_entry.entry.chain_id.to::<alloy_primitives::ChainId>(),
            address: list_entry.entry.address,
            nonce: list_entry.entry.nonce,
        };

        self.try_create_event(
            event,
            ExecEvent::TransactionAuthorizationListEntry {
                txn_index,
                authorization_list_index: list_entry.index,
                entry: eip7702::SignedAuthorization::new_unchecked(
                    authorization,
                    if list_entry.entry.y_parity { 1 } else { 0 },
                    list_entry.entry.r,
                    list_entry.entry.s,
                ),
                authority: if list_entry.is_valid_authority {
                    Some(list_entry.entry.address)
                } else {
                    None
                },
            },
        )
    }

    fn act_on_txn_header_end(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::TransactionHeaderEnd { txn_index },
        }
    }

    fn act_on_txn_reject(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let reject_code: u32 =
            unsafe { *(payload.as_ptr() as *const exec_event_ctypes::txn_reject) };
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        self.try_create_event(
            event,
            ExecEvent::TransactionReject {
                txn_index,
                reject_code,
            },
        )
    }

    fn act_on_txn_perf_evm_enter(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::TransactionPerfEvmEnter { txn_index },
        }
    }

    fn act_on_txn_perf_evm_exit(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::TransactionPerfEvmExit { txn_index },
        }
    }

    fn act_on_txn_evm_output(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let txn_evm_output =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_evm_output) };
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        self.try_create_event(
            event,
            ExecEvent::TransactionEvmOutput {
                txn_index,
                status: alloy_consensus::Eip658Value::Eip658(txn_evm_output.receipt.status),
                log_count: txn_evm_output.receipt.log_count as usize,
                call_frame_count: txn_evm_output.call_frame_count as usize,
                txn_gas_used: txn_evm_output.receipt.gas_used as u128,
            },
        )
    }

    fn act_on_txn_log(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        use alloy_primitives::Log;
        const LOG_HEADER_SIZE: usize = size_of::<exec_event_ctypes::txn_log>();
        const TOPIC_SIZE: usize = size_of::<B256>();
        let payload = self.reader.payload_peek(&event);
        let payload_base: *const u8 = payload.as_ptr();
        let txn_no = event.content_ext[flow_type::TXN_ID as usize] - 1;
        let c_log_header = unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_log) };
        let topics: &[B256] = unsafe {
            let topic_base = payload_base.wrapping_add(LOG_HEADER_SIZE) as *const B256;
            std::slice::from_raw_parts(topic_base, c_log_header.topic_count as usize)
        };
        let topic_length_bytes: usize = TOPIC_SIZE * c_log_header.topic_count as usize;
        let data_slice: &[u8] = unsafe {
            let data_base = payload_base.wrapping_add(LOG_HEADER_SIZE + topic_length_bytes);
            std::slice::from_raw_parts(data_base, c_log_header.data_length as usize)
        };
        let data: Bytes = Bytes::copy_from_slice(data_slice);
        self.try_create_event(
            event,
            ExecEvent::TransactionLog {
                txn_index: txn_no,
                log_index: c_log_header.index,
                log: Log::new_unchecked(c_log_header.address, Vec::from(topics), data),
            },
        )
    }

    fn act_on_txn_call_frame(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        const CALL_FRAME_HEADER_SIZE: usize = size_of::<exec_event_ctypes::txn_call_frame>();
        let payload = self.reader.payload_peek(&event);
        let payload_base: *const u8 = payload.as_ptr();
        let txn_no = event.content_ext[flow_type::TXN_ID as usize] - 1;
        let c_call_frame_header =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::txn_call_frame) };
        let input_slice: &[u8] = unsafe {
            let input_base = payload_base.wrapping_add(CALL_FRAME_HEADER_SIZE);
            std::slice::from_raw_parts(input_base, c_call_frame_header.input_length as usize)
        };
        let input: Bytes = Bytes::copy_from_slice(input_slice);
        let return_slice: &[u8] = unsafe {
            let return_base = payload_base.wrapping_add(CALL_FRAME_HEADER_SIZE + input.len());
            std::slice::from_raw_parts(return_base, c_call_frame_header.return_length as usize)
        };
        let return_value: Bytes = Bytes::copy_from_slice(return_slice);
        self.try_create_event(
            event,
            ExecEvent::TransactionCallFrame {
                txn_index: txn_no,
                call_frame_index: c_call_frame_header.index,
                call_frame: CallFrame {
                    opcode: c_call_frame_header.opcode,
                    caller: c_call_frame_header.caller,
                    call_target: c_call_frame_header.call_target,
                    value: c_call_frame_header.value,
                    gas: c_call_frame_header.gas,
                    gas_used: c_call_frame_header.gas_used,
                    evmc_status_code: c_call_frame_header.evmc_status,
                    depth: c_call_frame_header.depth,
                    input,
                    return_value,
                },
            },
        )
    }

    fn act_on_txn_end(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let txn_index = event.content_ext[flow_type::TXN_ID as usize] - 1;
        PollResult::Ready {
            seqno: event.seqno,
            event: ExecEvent::TransactionEnd { txn_index },
        }
    }

    fn act_on_account_access_header(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let list_header =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::account_access_list_header) };
        self.try_create_event(
            event,
            ExecEvent::AccountAccessListHeader {
                access_context: make_account_access_context(&event, list_header.access_context),
                entry_count: list_header.entry_count,
            },
        )
    }

    fn act_on_account_access(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let account_access =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::account_access) };
        self.try_create_event(
            event,
            ExecEvent::AccountAccess {
                account_index: account_access.index,
                access_context: make_account_access_context(&event, account_access.access_context),
                access_info: AccountAccess {
                    address: account_access.address,
                    original_nonce: account_access.prestate.nonce,
                    modified_nonce: if account_access.is_nonce_modified {
                        Some(account_access.modified_nonce)
                    } else {
                        None
                    },
                    original_balance: account_access.prestate.balance,
                    modified_balance: if account_access.is_balance_modified {
                        Some(account_access.modified_balance)
                    } else {
                        None
                    },
                    code_hash: account_access.prestate.code_hash,
                    storage_key_count: account_access.storage_key_count,
                    transient_key_count: account_access.transient_count,
                },
            },
        )
    }

    fn act_on_storage_access(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        let payload = self.reader.payload_peek(&event);
        let storage_access =
            unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::storage_access) };
        self.try_create_event(
            event,
            ExecEvent::StorageAccess {
                access_context: make_account_access_context(&event, storage_access.access_context),
                account_index: event.content_ext[flow_type::ACCOUNT_INDEX as usize] as u32,
                storage_index: storage_access.index,
                access_info: StorageAccess {
                    address: storage_access.address,
                    is_transient: storage_access.transient,
                    key: storage_access.key,
                    original_value: storage_access.start_value,
                    modified_value: if storage_access.modified {
                        Some(storage_access.end_value)
                    } else {
                        None
                    },
                },
            },
        )
    }

    fn act_on_evm_error(&'_ mut self, event: monad_event_descriptor) -> PollResult {
        // This does the same thing as act_on_*_reject, but for a different
        // reason: EVM_ERROR means that execution failed for a reason other
        // than a validation failure, i.e., the execution daemon experienced
        // some kind of fundamental error (e.g., out of memory).
        let payload = self.reader.payload_peek(&event);
        let exec_error = unsafe { &*(payload.as_ptr() as *const exec_event_ctypes::evm_error) };
        self.try_create_event(
            event,
            ExecEvent::EvmError {
                domain_id: exec_error.domain_id,
                status_code: exec_error.status_code,
                txn_id: event.content_ext[flow_type::TXN_ID as usize],
            },
        )
    }

    fn try_create_event(
        &'_ mut self,
        raw_event: monad_event_descriptor,
        exec_event: ExecEvent,
    ) -> PollResult {
        if self.reader.payload_check(&raw_event) {
            PollResult::Ready {
                seqno: raw_event.seqno,
                event: exec_event,
            }
        } else {
            self.clear_finalized_buffer();
            PollResult::PayloadExpired {
                expired_seqno: self.reader.read_last_seqno,
                last_write_seqno: self.reader.reset(),
                payload_offset: raw_event.payload_buf_offset,
                buffer_window_start: self.reader.get_buffer_window_start(),
            }
        }
    }

    fn clear_finalized_buffer(&'_ mut self) {
        for pm in &mut self.finalized_buffer {
            pm.take();
        }
        self.finalized_count = 0;
    }
}

fn create_block_tag(t: &exec_event_ctypes::block_tag) -> BlockTag {
    BlockTag {
        id: MonadBlockId(t.id),
        block_number: t.block_number,
    }
}

fn create_alloy_tx_envelope(
    txn_hash: &B256,
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
    blob_versioned_hashes: Vec<B256>,
) -> alloy_consensus::TxEnvelope {
    use alloy_consensus::{Signed, TxEnvelope, TxType};
    let txn_type = TxType::try_from(txn_header.txn_type as u8).expect("bad transaction type");
    let signature = alloy_primitives::PrimitiveSignature::from_scalars_and_parity(
        B256::from(txn_header.r),
        B256::from(txn_header.s),
        txn_header.y_parity,
    );
    match txn_type {
        TxType::Legacy => TxEnvelope::Legacy(Signed::new_unchecked(
            create_tx_legacy(txn_header, input),
            signature,
            *txn_hash,
        )),
        TxType::Eip1559 => TxEnvelope::Eip1559(Signed::new_unchecked(
            create_tx_eip1559(txn_header, input),
            signature,
            *txn_hash,
        )),
        TxType::Eip2930 => TxEnvelope::Eip2930(Signed::new_unchecked(
            create_tx_eip2930(txn_header, input),
            signature,
            *txn_hash,
        )),
        TxType::Eip4844 => TxEnvelope::Eip4844(Signed::new_unchecked(
            TxEip4844Variant::TxEip4844(create_tx_eip4484(
                txn_header,
                input,
                blob_versioned_hashes,
            )),
            signature,
            *txn_hash,
        )),
        TxType::Eip7702 => TxEnvelope::Eip7702(Signed::new_unchecked(
            create_tx_eip7702(txn_header, input),
            signature,
            *txn_hash,
        )),
        _ => panic!("transaction type is not supported!"),
    }
}

fn make_account_access_context(
    event: &monad_event_descriptor,
    context_code: exec_event_ctypes::account_access_context,
) -> AccountAccessContext {
    use exec_event_ctypes::account_access_context::*;
    let txn_id = event.content_ext[flow_type::TXN_ID as usize];
    match context_code {
        BLOCK_PROLOGUE => AccountAccessContext::BlockPrologue,
        TRANSACTION => AccountAccessContext::Transaction(txn_id - 1),
        BLOCK_EPILOGUE => AccountAccessContext::BlockEpilogue,
    }
}

fn create_tx_legacy(
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
) -> alloy_consensus::TxLegacy {
    alloy_consensus::TxLegacy {
        chain_id: match txn_header.chain_id {
            U256::ZERO => None,
            _ => Some(txn_header.chain_id.to::<alloy_primitives::ChainId>()),
        },
        nonce: txn_header.nonce,
        gas_price: txn_header.max_fee_per_gas.to::<u128>(),
        gas_limit: txn_header.gas_limit,
        to: if txn_header.is_contract_creation {
            TxKind::Create
        } else {
            TxKind::Call(txn_header.to)
        },
        value: txn_header.value,
        input,
    }
}

fn create_tx_eip1559(
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
) -> alloy_consensus::TxEip1559 {
    let mut txn_eip_1559 = alloy_consensus::TxEip1559 {
        chain_id: txn_header.chain_id.to::<alloy_primitives::ChainId>(),
        nonce: txn_header.nonce,
        gas_limit: txn_header.gas_limit,
        max_fee_per_gas: txn_header.max_fee_per_gas.to::<u128>(),
        max_priority_fee_per_gas: txn_header.max_priority_fee_per_gas.to::<u128>(),
        to: if txn_header.is_contract_creation {
            TxKind::Create
        } else {
            TxKind::Call(txn_header.to)
        },
        value: txn_header.value,
        access_list: alloy_eips::eip2930::AccessList::default(),
        input,
    };
    txn_eip_1559
        .access_list
        .0
        .reserve(txn_header.access_list_count as usize);
    txn_eip_1559
}

fn create_tx_eip2930(
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
) -> alloy_consensus::TxEip2930 {
    let mut txn_eip_2930 = alloy_consensus::TxEip2930 {
        chain_id: txn_header.chain_id.to::<alloy_primitives::ChainId>(),
        nonce: txn_header.nonce,
        gas_price: txn_header.max_fee_per_gas.to::<u128>(),
        gas_limit: txn_header.gas_limit,
        to: if txn_header.is_contract_creation {
            TxKind::Create
        } else {
            TxKind::Call(txn_header.to)
        },
        value: txn_header.value,
        access_list: eip2930::AccessList::default(),
        input,
    };
    txn_eip_2930
        .access_list
        .0
        .reserve(txn_header.access_list_count as usize);
    txn_eip_2930
}

fn create_tx_eip4484(
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
    blob_versioned_hashes: Vec<B256>,
) -> alloy_consensus::TxEip4844 {
    let mut txn_eip_4844 = alloy_consensus::TxEip4844 {
        chain_id: txn_header.chain_id.to::<alloy_primitives::ChainId>(),
        nonce: txn_header.nonce,
        gas_limit: txn_header.gas_limit,
        max_fee_per_gas: txn_header.max_fee_per_gas.to::<u128>(),
        max_priority_fee_per_gas: txn_header.max_priority_fee_per_gas.to::<u128>(),
        to: txn_header.to,
        value: txn_header.value,
        access_list: eip2930::AccessList::default(),
        blob_versioned_hashes,
        max_fee_per_blob_gas: txn_header.max_fee_per_gas.to::<u128>(),
        input,
    };
    txn_eip_4844
        .access_list
        .0
        .reserve(txn_header.access_list_count as usize);
    txn_eip_4844
}

fn create_tx_eip7702(
    txn_header: &eth_ctypes::eth_txn_header,
    input: Bytes,
) -> alloy_consensus::TxEip7702 {
    let mut txn_eip_7702 = alloy_consensus::TxEip7702 {
        chain_id: txn_header.chain_id.to::<alloy_primitives::ChainId>(),
        nonce: txn_header.nonce,
        gas_limit: txn_header.gas_limit,
        max_fee_per_gas: txn_header.max_fee_per_gas.to::<u128>(),
        max_priority_fee_per_gas: txn_header.max_priority_fee_per_gas.to::<u128>(),
        to: txn_header.to,
        value: txn_header.value,
        access_list: eip2930::AccessList::default(),
        authorization_list: Vec::new(),
        input,
    };
    txn_eip_7702
        .access_list
        .0
        .reserve(txn_header.access_list_count as usize);
    txn_eip_7702
        .authorization_list
        .reserve(txn_header.auth_list_count as usize);
    txn_eip_7702
}
