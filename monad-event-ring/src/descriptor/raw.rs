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

use crate::{
    ffi::{monad_event_descriptor, monad_event_ring_payload_check, monad_event_ring_payload_peek},
    EventDescriptorPayload, RawEventRing,
};

#[derive(Debug)]
pub(crate) struct RawEventDescriptor<'ring> {
    inner: monad_event_descriptor,
    ring: &'ring RawEventRing,
}

impl<'ring> RawEventDescriptor<'ring> {
    pub(crate) fn new(
        ring: &'ring RawEventRing,
        c_event_descriptor: monad_event_descriptor,
    ) -> Self {
        Self {
            inner: c_event_descriptor,
            ring,
        }
    }

    pub(crate) fn info(&self) -> RawEventDescriptorInfo {
        RawEventDescriptorInfo {
            seqno: self.inner.seqno,
            event_type: self.inner.event_type,
            record_epoch_nanos: self.inner.record_epoch_nanos,
            user: self.inner.user,
        }
    }

    pub(crate) fn try_filter_map<T>(
        &self,
        f: impl FnOnce(RawEventDescriptorInfo, &[u8]) -> T,
    ) -> EventDescriptorPayload<T> {
        let info = self.info();

        let Some(bytes) = monad_event_ring_payload_peek(&self.ring.inner, &self.inner) else {
            return EventDescriptorPayload::Expired;
        };

        let value = f(info, bytes);

        if monad_event_ring_payload_check(&self.ring.inner, &self.inner) {
            EventDescriptorPayload::Payload(value)
        } else {
            EventDescriptorPayload::Expired
        }
    }
}

pub(crate) struct RawEventDescriptorInfo {
    pub seqno: u64,

    pub event_type: u16,

    pub record_epoch_nanos: u64,

    pub user: [u64; 4],
}
