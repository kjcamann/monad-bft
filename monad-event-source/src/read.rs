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

use std::marker::PhantomData;

use monad_event::{EventDescriptorRead, RawEventDescriptor, RawEventDescriptorInfo};
use monad_event_capture::{EventCapturePayload, EventCaptureRawPayload};
use monad_event_ring::{EventRingPayload, RawEventRing};

use crate::EventSourceResult;

/// TODO
pub struct EventSourceRead<'buf> {
    _phantom: PhantomData<RawEventSourceRead<'buf>>,
}

impl<'buf> EventDescriptorRead for EventSourceRead<'buf> {
    type Raw = RawEventSourceRead<'buf>;

    type Result<T> = EventSourceResult<T>;

    fn try_filter_map<T>(
        this: &RawEventDescriptor<Self::Raw>,
        f: impl FnOnce(RawEventDescriptorInfo, &[u8]) -> T,
    ) -> Self::Result<T> {
        match &this.buffer {
            RawEventSourceRead::Capture(raw_payload) => {
                EventSourceResult::Ok(EventCapturePayload::try_filter_map(
                    &RawEventDescriptor {
                        inner: this.inner,
                        buffer: *raw_payload,
                    },
                    f,
                ))
            }
            RawEventSourceRead::Ring(raw_event_ring) => {
                EventSourceResult::from(EventRingPayload::<'buf>::try_filter_map(
                    &RawEventDescriptor {
                        inner: this.inner,
                        buffer: *raw_event_ring,
                    },
                    f,
                ))
            }
        }
    }

    fn result_ok<T>(value: T) -> Self::Result<T> {
        Self::Result::Ok(value)
    }

    fn result_map<T, U>(result: Self::Result<T>, f: impl FnOnce(T) -> U) -> Self::Result<U> {
        match result {
            EventSourceResult::Ok(value) => EventSourceResult::Ok(f(value)),
            EventSourceResult::Expired => EventSourceResult::Expired,
        }
    }

    fn result_and_then<T, U>(
        result: Self::Result<T>,
        f: impl FnOnce(T) -> Self::Result<U>,
    ) -> Self::Result<U> {
        match result {
            EventSourceResult::Ok(value) => f(value),
            EventSourceResult::Expired => EventSourceResult::Expired,
        }
    }
}

pub enum RawEventSourceRead<'buf> {
    Capture(EventCaptureRawPayload<'buf>),
    Ring(&'buf RawEventRing),
}

impl<'buf> From<EventCaptureRawPayload<'buf>> for RawEventSourceRead<'buf> {
    fn from(value: EventCaptureRawPayload<'buf>) -> Self {
        Self::Capture(value)
    }
}
