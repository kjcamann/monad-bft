// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use itertools::Itertools;
use monad_event_ring::{EventDescriptor, EventPayloadResult};
use state::AccountAccessReassemblyState;

use self::state::{BlockReassemblyState, TxnOutputReassemblyState, TxnReassemblyState};
use super::{BlockBuilderError, BlockBuilderResult, ReassemblyError};
use crate::{
    ffi::{
        self, monad_c_access_list_entry, monad_c_auth_list_entry, monad_c_bytes32,
        monad_exec_account_access, monad_exec_account_access_list_header,
        monad_exec_storage_access, monad_exec_txn_access_list_entry,
        monad_exec_txn_auth_list_entry, monad_exec_txn_evm_output, monad_exec_txn_header_start,
    },
    ExecEvent, ExecEventDecoder, ExecEventRef, ExecutedAccountAccess, ExecutedBlock,
    ExecutedStorageAccess, ExecutedTxn, ExecutedTxnAccessListEntry, ExecutedTxnCallFrame,
    ExecutedTxnLog, ExecutedTxnSignedAuthorization,
};

mod state;

/// Reassembles execution events from event ring event descriptors into full execution blocks.
#[derive(Debug)]
pub struct ExecutedBlockBuilder {
    state: Option<BlockReassemblyState>,
    include_call_frames: bool,
    include_accesses: bool,
}

impl ExecutedBlockBuilder {
    /// Creates a new [`ExecutedBlockBuilder`].
    pub fn new(include_call_frames: bool, include_accesses: bool) -> Self {
        Self {
            state: None,
            include_call_frames,
            include_accesses,
        }
    }

    /// Processes the execution event in the provided event descriptor.
    pub fn process_event_descriptor<'ring>(
        &mut self,
        event_descriptor: &EventDescriptor<'ring, ExecEventDecoder>,
    ) -> Option<BlockBuilderResult<ExecutedBlock>> {
        let filter_fn = match (self.include_call_frames, self.include_accesses) {
            (true, true) => Self::select_block_event_refs::<true, true>,
            (true, false) => Self::select_block_event_refs::<true, false>,
            (false, true) => Self::select_block_event_refs::<false, true>,
            (false, false) => Self::select_block_event_refs::<false, false>,
        };

        match event_descriptor.try_filter_map(filter_fn) {
            EventPayloadResult::Ready(Some(exec_event)) => self.process_exec_event(exec_event),
            EventPayloadResult::Ready(None) => None,
            EventPayloadResult::Expired => {
                self.reset();

                Some(Err(BlockBuilderError::PayloadExpired))
            }
        }
    }

    /// Resets the state of the block builder.
    ///
    /// <div class="warning">
    ///
    /// This method **must** be called before giving [`self`](ExecutedBlockBuilder) an event
    /// descriptor that is out of order. Failing to do so will cause the [`ExecutedBlockBuilder`] to
    /// eventually produce a [`BlockBuilderError::ImplicitDrop`] as the block reassembly will fail.
    ///
    /// See [`BlockBuilderError::ImplicitDrop`] and [`ReassemblyError`] for more details.
    ///
    /// </div>
    pub fn reset(&mut self) {
        self.state = None;
    }

    fn select_block_event_refs<const INCLUDE_CALL_FRAMES: bool, const INCLUDE_ACCESSES: bool>(
        event_ref: ExecEventRef<'_>,
    ) -> Option<ExecEvent> {
        match event_ref {
            ExecEventRef::RecordError(..) => unimplemented!(),

            ExecEventRef::BlockPerfEvmEnter
            | ExecEventRef::BlockPerfEvmExit
            | ExecEventRef::BlockQC(_)
            | ExecEventRef::BlockFinalized(_)
            | ExecEventRef::BlockVerified(_)
            | ExecEventRef::TxnHeaderEnd
            | ExecEventRef::TxnPerfEvmEnter
            | ExecEventRef::TxnPerfEvmExit => None,

            ExecEventRef::TxnCallFrame { .. } if !INCLUDE_CALL_FRAMES => None,

            ExecEventRef::AccountAccessListHeader { .. }
            | ExecEventRef::AccountAccess { .. }
            | ExecEventRef::StorageAccess { .. }
                if !INCLUDE_ACCESSES =>
            {
                None
            }

            event => Some(event.into_owned()),
        }
    }

    fn process_exec_event(
        &mut self,
        exec_event: ExecEvent,
    ) -> Option<BlockBuilderResult<ExecutedBlock>> {
        match exec_event {
            ExecEvent::RecordError(..) => unreachable!(),

            ExecEvent::BlockPerfEvmEnter
            | ExecEvent::BlockPerfEvmExit
            | ExecEvent::BlockQC(_)
            | ExecEvent::BlockFinalized(_)
            | ExecEvent::BlockVerified(_)
            | ExecEvent::TxnHeaderEnd
            | ExecEvent::TxnPerfEvmEnter
            | ExecEvent::TxnPerfEvmExit => unreachable!(),

            ExecEvent::TxnCallFrame { .. } if !self.include_call_frames => unreachable!(),

            ExecEvent::AccountAccessListHeader { .. }
            | ExecEvent::AccountAccess { .. }
            | ExecEvent::StorageAccess { .. }
                if !self.include_accesses =>
            {
                unreachable!()
            }

            ExecEvent::BlockStart(block_header) => {
                if let Some(dropped_state) = self.state.take() {
                    return Some(Err(BlockBuilderError::ImplicitDrop {
                        block: dropped_state.start,
                        reassembly_error: ReassemblyError::UnterminatedBlock {
                            unexpected_header: block_header,
                        },
                    }));
                }

                let txn_count = block_header.eth_block_input.txn_count.try_into().unwrap();

                let mut txns = Vec::with_capacity(txn_count);
                txns.resize_with(txn_count, || None);

                self.state = Some(BlockReassemblyState {
                    start: block_header,
                    txns: txns.into_boxed_slice(),
                });

                None
            }
            ExecEvent::BlockReject(_) => {
                let state = self.state.as_mut()?;

                self.reset();

                Some(Err(BlockBuilderError::Rejected))
            }
            ExecEvent::BlockEnd(block_result) => {
                let BlockReassemblyState {
                    start: header,
                    txns,
                } = self.state.take()?;

                Some(Ok(ExecutedBlock {
                    start: header,
                    end: block_result,
                    txns: txns
                        .into_vec()
                        .into_iter()
                        .map(|txn_opt| {
                            txn_opt.expect("ExecutedBlockBuilder received TxnStart for txn")
                        })
                        .map(
                            |TxnReassemblyState {
                                 hash,
                                 sender,
                                 header,
                                 input,
                                 access_list,
                                 authorization_list,
                                 output,
                             }| {
                                let TxnOutputReassemblyState {
                                    receipt,
                                    logs,
                                    call_frames,
                                    account_accesses,
                                } = output.expect("ExecutedBlockBuilder populated output");

                                ExecutedTxn {
                                    hash,
                                    sender,
                                    header,
                                    input,
                                    access_list: access_list.into_boxed_slice(),
                                    authorization_list: authorization_list.into_boxed_slice(),
                                    receipt,
                                    logs: logs
                                        .into_vec()
                                        .into_iter()
                                        .map(|log| log.expect("ExecutedBlockBuilder populated log"))
                                        .collect_vec()
                                        .into_boxed_slice(),
                                    call_frames: call_frames.map(|call_frames| {
                                        call_frames
                                            .into_vec()
                                            .into_iter()
                                            .map(|call_frame| {
                                                call_frame.expect(
                                                    "ExecutedBlockBuilder populated call_frame",
                                                )
                                            })
                                            .collect_vec()
                                            .into_boxed_slice()
                                    }),
                                    account_accesses: account_accesses.map(|account_accesses| {
                                        account_accesses
                                            .into_vec()
                                            .into_iter()
                                            .map(|account_access| {
                                                let AccountAccessReassemblyState {
                                                    address,
                                                    is_balance_modified,
                                                    is_nonce_modified,
                                                    prestate,
                                                    modified_balance,
                                                    modified_nonce,
                                                    storage_accesses,
                                                    transient_accesses,
                                                } = account_access.expect(
                                                    "ExecutedBlockBuilder populated account_access",
                                                );

                                                ExecutedAccountAccess {
                                                    address,
                                                    is_balance_modified,
                                                    is_nonce_modified,
                                                    prestate,
                                                    modified_balance,
                                                    modified_nonce,
                                                    storage_accesses: storage_accesses.into_vec().into_iter().map(|storage_access| storage_access.expect("ExecutedBlockBuilder populated storage_access")).collect_vec().into_boxed_slice(),
                                                    transient_accesses: transient_accesses.into_vec().into_iter().map(|storage_access| storage_access.expect("ExecutedBlockBuilder populated transient_accesses")).collect_vec().into_boxed_slice(),
                                                }
                                            })
                                            .collect_vec()
                                            .into_boxed_slice()
                                    }),
                                }
                            },
                        )
                        .collect(),
                }))
            }
            ExecEvent::TxnHeaderStart {
                txn_index: index,
                txn_header_start: txn_start,
                data_bytes,
                blob_bytes: _,
            } => {
                let state = self.state.as_mut()?;

                let monad_exec_txn_header_start {
                    txn_hash,
                    sender,
                    txn_header,
                } = txn_start;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(index).unwrap())
                    .expect("ExecutedBlockBuilder TxnStart txn_index within bounds");

                assert!(txn_ref.is_none());

                *txn_ref = Some(TxnReassemblyState {
                    hash: txn_hash,
                    sender,
                    header: txn_header,
                    input: data_bytes,
                    access_list: Vec::default(),
                    authorization_list: Vec::default(),
                    output: None,
                });

                None
            }
            ExecEvent::TxnAccessListEntry {
                txn_index,
                txn_access_list_entry:
                    monad_exec_txn_access_list_entry {
                        index,
                        entry:
                            monad_c_access_list_entry {
                                address,
                                storage_key_count,
                            },
                    },
                storage_key_bytes,
            } => {
                let state = self.state.as_mut()?;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                    .expect("ExecutedBlockBuilder TxnAccessListEntry txn_index within bounds")
                    .as_mut()
                    .expect("ExecutedBlockBuilder TxnAccessListEntry txn_index populated from preceding TxnStart");

                assert_eq!(txn_ref.access_list.len() as u32, index);

                let storage_keys = storage_key_bytes
                    .into_vec()
                    .into_iter()
                    .chunks(std::mem::size_of::<monad_c_bytes32>())
                    .into_iter()
                    .map(|chunk| monad_c_bytes32 {
                        bytes: chunk.collect_vec().try_into().unwrap(),
                    })
                    .collect_vec()
                    .into_boxed_slice();

                assert_eq!(storage_keys.len(), storage_key_count as usize);

                txn_ref.access_list.push(ExecutedTxnAccessListEntry {
                    address,
                    storage_keys,
                });

                None
            }
            ExecEvent::TxnAuthListEntry {
                txn_index,
                txn_auth_list_entry:
                    monad_exec_txn_auth_list_entry {
                        index,
                        entry:
                            monad_c_auth_list_entry {
                                chain_id,
                                address,
                                nonce,
                                y_parity,
                                r,
                                s,
                            },
                        authority: _,
                        is_valid_authority: _,
                    },
            } => {
                let state = self.state.as_mut()?;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                    .expect("ExecutedBlockBuilder TxnAuthListEntry txn_index within bounds")
                    .as_mut()
                    .expect("ExecutedBlockBuilder TxnAuthListEntry txn_index populated from preceding TxnStart");

                assert_eq!(txn_ref.authorization_list.len() as u32, index);

                txn_ref
                    .authorization_list
                    .push(ExecutedTxnSignedAuthorization {
                        chain_id,
                        address,
                        nonce,
                        y_parity,
                        r,
                        s,
                    });

                None
            }
            ExecEvent::TxnReject { .. } => {
                let state = self.state.as_mut()?;

                self.reset();

                Some(Err(BlockBuilderError::Rejected))
            }
            ExecEvent::TxnEvmOutput {
                txn_index,
                output:
                    monad_exec_txn_evm_output {
                        receipt,
                        call_frame_count,
                    },
            } => {
                let state = self.state.as_mut()?;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                    .expect("ExecutedBlockBuilder TxnReceipt txn_index within bounds")
                    .as_mut()
                    .expect("ExecutedBlockBuilder TxnReceipt txn_index populated from preceding TxnStart");

                assert!(txn_ref.output.is_none());

                txn_ref.output = Some(TxnOutputReassemblyState {
                    receipt,
                    logs: (0..receipt.log_count as usize)
                        .map(|_| None)
                        .collect_vec()
                        .into_boxed_slice(),
                    call_frames: self.include_call_frames.then(|| {
                        (0..call_frame_count as usize)
                            .map(|_| None)
                            .collect_vec()
                            .into_boxed_slice()
                    }),
                    account_accesses: None,
                });

                None
            }
            ExecEvent::TxnLog {
                txn_index,
                txn_log,
                topic_bytes,
                data_bytes,
            } => {
                let state = self.state.as_mut()?;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                    .expect("ExecutedBlockBuilder TxnLog txn_index within bounds")
                    .as_mut()
                    .expect(
                        "ExecutedBlockBuilder TxnLog txn_index populated from preceding TxnStart",
                    );

                let txn_output = txn_ref.output.as_mut().expect(
                    "ExecutedBlockBuilder TxnLog output populated from preceding TxnEvmOutput",
                );

                let existing_txn_log = txn_output
                    .logs
                    .get_mut(txn_log.index as usize)
                    .expect("ExecutedBlockBuilder TxnLog index within bounds")
                    .replace(ExecutedTxnLog {
                        address: txn_log.address,
                        topic: topic_bytes
                            .into_vec()
                            .into_iter()
                            .chunks(std::mem::size_of::<monad_c_bytes32>())
                            .into_iter()
                            .take(4)
                            .map(|chunk| monad_c_bytes32 {
                                bytes: chunk.collect_vec().try_into().unwrap(),
                            })
                            .collect(),
                        data: data_bytes,
                    });

                assert!(existing_txn_log.is_none());

                None
            }
            ExecEvent::TxnCallFrame {
                txn_index,
                txn_call_frame,
                input_bytes,
                return_bytes,
            } => {
                let state = self.state.as_mut()?;

                let txn_ref = state
                    .txns
                    .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                    .expect("ExecutedBlockBuilder TxnCallFrame txn_index within bounds")
                    .as_mut()
                    .expect(
                        "ExecutedBlockBuilder TxnCallFrame txn_index populated from preceding TxnStart",
                    );

                let txn_output = txn_ref.output.as_mut().expect(
                    "ExecutedBlockBuilder TxnCallFrame output populated from preceding TxnEvmOutput",
                );

                let txn_call_frames = txn_output
                    .call_frames
                    .as_mut()
                    .expect("ExecutedBlockBuilder TxnReassemblyState call_frames set to Some");

                let existing_txn_call_frame = txn_call_frames
                    .get_mut(txn_call_frame.index as usize)
                    .expect("ExecutedBlockBuilder TxnCallFrame index within bounds")
                    .replace(ExecutedTxnCallFrame {
                        call_frame: txn_call_frame,
                        input: input_bytes,
                        r#return: return_bytes,
                    });

                assert!(existing_txn_call_frame.is_none());

                None
            }
            ExecEvent::TxnEnd => None,
            ExecEvent::AccountAccessListHeader {
                txn_index,
                account_access_list_header:
                    monad_exec_account_access_list_header {
                        entry_count,
                        access_context,
                    },
            } => {
                let state = self.state.as_mut()?;

                match access_context {
                    ffi::MONAD_ACCT_ACCESS_BLOCK_PROLOGUE => {
                        assert!(txn_index.is_none());
                    }
                    ffi::MONAD_ACCT_ACCESS_TRANSACTION => {
                        let txn_index = txn_index.expect(
                            "ExecutedBlockBuilder AccountAccessListHeader txn_index is Some",
                        );

                        let txn_ref = state
                            .txns
                            .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                            .expect("ExecutedBlockBuilder AccountAccessListHeader txn_index within bounds")
                            .as_mut()
                            .expect(
                                "ExecutedBlockBuilder AccountAccessListHeader txn_index populated from preceding TxnStart",
                            );

                        let txn_output = txn_ref.output.as_mut().expect(
                            "ExecutedBlockBuilder AccountAccessListHeader output populated from preceding TxnEvmOutput",
                        );

                        assert!(txn_output.account_accesses.is_none());

                        txn_output.account_accesses = Some(
                            (0..entry_count as usize)
                                .map(|_| None)
                                .collect_vec()
                                .into_boxed_slice(),
                        );
                    }
                    ffi::MONAD_ACCT_ACCESS_BLOCK_EPILOGUE => {
                        assert!(txn_index.is_none());
                    }
                    access_context => {
                        panic!("ExecutedBlockBuilder encountered unknown access_context {access_context}")
                    }
                }

                None
            }
            ExecEvent::AccountAccess {
                txn_index,
                account_access:
                    monad_exec_account_access {
                        index: account_index,
                        address,
                        access_context,
                        is_balance_modified,
                        is_nonce_modified,
                        prestate,
                        modified_balance,
                        modified_nonce,
                        storage_key_count,
                        transient_count,
                    },
            } => {
                let state = self.state.as_mut()?;

                match access_context {
                    ffi::MONAD_ACCT_ACCESS_BLOCK_PROLOGUE => {
                        assert!(txn_index.is_none());
                    }
                    ffi::MONAD_ACCT_ACCESS_TRANSACTION => {
                        let txn_index = txn_index
                            .expect("ExecutedBlockBuilder AccountAccess txn_index is Some");

                        let txn_ref = state
                            .txns
                            .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                            .expect("ExecutedBlockBuilder AccountAccess txn_index within bounds")
                            .as_mut()
                            .expect(
                                "ExecutedBlockBuilder AccountAccess txn_index populated from preceding TxnStart",
                            );

                        let txn_output = txn_ref.output.as_mut().expect(
                            "ExecutedBlockBuilder AccountAccess output populated from preceding TxnEvmOutput",
                        );

                        let txn_account_accesses = txn_output.account_accesses.as_mut().expect(
                            "ExecutedBlockBuilder AccountAccess output account_accesses set to Some",
                        );

                        let existing_txn_account_access = txn_account_accesses
                            .get_mut(account_index as usize)
                            .expect(
                                "ExecutedBlockBuilder AccountAccess account_index within bounds",
                            )
                            .replace(AccountAccessReassemblyState {
                                address,
                                is_balance_modified,
                                is_nonce_modified,
                                prestate,
                                modified_balance,
                                modified_nonce,
                                storage_accesses: (0..storage_key_count)
                                    .map(|_| None)
                                    .collect_vec()
                                    .into_boxed_slice(),
                                transient_accesses: (0..transient_count)
                                    .map(|_| None)
                                    .collect_vec()
                                    .into_boxed_slice(),
                            });

                        assert!(existing_txn_account_access.is_none());
                    }
                    ffi::MONAD_ACCT_ACCESS_BLOCK_EPILOGUE => {
                        assert!(txn_index.is_none());
                    }
                    access_context => {
                        panic!("ExecutedBlockBuilder encountered unknown access_context {access_context}")
                    }
                }

                None
            }
            ExecEvent::StorageAccess {
                txn_index,
                account_index,
                storage_access:
                    monad_exec_storage_access {
                        address,
                        index: storage_index,
                        access_context,
                        modified,
                        transient,
                        key,
                        start_value,
                        end_value,
                    },
            } => {
                let state = self.state.as_mut()?;

                match access_context {
                    ffi::MONAD_ACCT_ACCESS_BLOCK_PROLOGUE => {
                        assert!(txn_index.is_none());
                    }
                    ffi::MONAD_ACCT_ACCESS_TRANSACTION => {
                        let txn_index = txn_index
                            .expect("ExecutedBlockBuilder StorageAccess txn_index is Some");

                        let txn_ref = state
                            .txns
                            .get_mut(TryInto::<usize>::try_into(txn_index).unwrap())
                            .expect("ExecutedBlockBuilder StorageAccess txn_index within bounds")
                            .as_mut()
                            .expect(
                                "ExecutedBlockBuilder StorageAccess txn_index populated from preceding TxnStart",
                            );

                        let txn_output = txn_ref.output.as_mut().expect(
                            "ExecutedBlockBuilder StorageAccess output populated from preceding TxnEvmOutput",
                        );

                        let txn_account_accesses = txn_output.account_accesses.as_mut().expect(
                            "ExecutedBlockBuilder StorageAccess output account_accesses set to Some",
                        );

                        let txn_account_access = txn_account_accesses
                            .get_mut(account_index as usize)
                            .expect(
                                "ExecutedBlockBuilder StorageAccess account_index within bounds",
                            )
                            .as_mut()
                            .expect("ExecutedBlockBuilder StorageAccess set to Some");

                        assert_eq!(txn_account_access.address, address);

                        let storage_accesses = if transient {
                            &mut txn_account_access.transient_accesses
                        } else {
                            &mut txn_account_access.storage_accesses
                        };

                        let existing_storage_access = storage_accesses
                            .get_mut(storage_index as usize)
                            .expect(
                                "ExecutedBlockBuilder StorageAccess storage_index within bounds",
                            )
                            .replace(ExecutedStorageAccess {
                                modified,
                                key,
                                start_value,
                                end_value,
                            });

                        assert!(existing_storage_access.is_none());
                    }
                    ffi::MONAD_ACCT_ACCESS_BLOCK_EPILOGUE => {
                        assert!(txn_index.is_none());
                    }
                    access_context => {
                        panic!("ExecutedBlockBuilder encountered unknown access_context {access_context}")
                    }
                }

                None
            }
            ExecEvent::EvmError(monad_exec_evm_error) => {
                let state = self.state.as_mut()?;

                unimplemented!("EvmError {monad_exec_evm_error:#?}");
            }
        }
    }
}

#[cfg(test)]
mod test {
    use monad_event_ring::{DecodedEventRing, EventNextResult};

    use crate::{block_builder::ExecutedBlockBuilder, BlockBuilderError, ExecSnapshotEventRing};

    fn run_block_builder(snapshot_name: &'static str, snapshot_zstd_bytes: &'static [u8]) {
        let snapshot =
            ExecSnapshotEventRing::new_from_zstd_bytes(snapshot_name, snapshot_zstd_bytes, None)
                .unwrap();

        let mut event_reader = snapshot.create_reader();

        let mut block_builder = ExecutedBlockBuilder::new(true, true);

        loop {
            let event_descriptor = match event_reader.next_descriptor() {
                EventNextResult::NotReady => break,
                EventNextResult::Gap => panic!("snapshot cannot gap"),
                EventNextResult::Ready(event_descriptor) => event_descriptor,
            };

            let Some(result) = block_builder.process_event_descriptor(&event_descriptor) else {
                continue;
            };

            match result {
                Ok(executed_block) => {
                    eprintln!("{executed_block:#?}");
                }
                Err(BlockBuilderError::Rejected) => {
                    panic!("snapshot does not contain blocks that are rejected")
                }
                Err(BlockBuilderError::PayloadExpired) => panic!("payload expired on snapshot"),
                Err(BlockBuilderError::ImplicitDrop { .. }) => {
                    unreachable!()
                }
            }
        }
    }

    #[test]
    fn basic_test_ethereum_mainnet() {
        const SNAPSHOT_NAME: &str = "ETHEREUM_MAINNET_30B_15M";
        const SNAPSHOT_ZSTD_BYTES: &[u8] =
            include_bytes!("../../../test/data/exec-events-emn-30b-15m/snapshot.zst");

        run_block_builder(SNAPSHOT_NAME, SNAPSHOT_ZSTD_BYTES);
    }

    #[ignore]
    #[test]
    fn basic_test_monad_testnet() {
        const SNAPSHOT_NAME: &str = "MONAD_DEVNET_500B_GENESIS";
        const SNAPSHOT_ZSTD_BYTES: &[u8] =
            include_bytes!("../../../test/data/exec-events-mdn-500b-genesis/snapshot.zst");

        run_block_builder(SNAPSHOT_NAME, SNAPSHOT_ZSTD_BYTES);
    }
}
