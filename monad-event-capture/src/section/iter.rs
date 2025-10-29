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

use monad_event::{
    ffi::monad_event_descriptor, EventDecoder, EventDescriptor, EventDescriptorRead,
    RawEventDescriptor, RawEventDescriptorInfo,
};

use crate::{
    ffi::{
        self, monad_evcap_event_iter, monad_evcap_event_iter_next, monad_evcap_event_section,
        monad_evcap_event_section_open_iterator, monad_evcap_read_result, monad_evcap_reader,
    },
    EventCaptureNextResult,
};

pub struct EventCaptureEventIter<'reader, 'section, D>
where
    D: EventDecoder,
{
    reader: &'reader monad_evcap_reader,
    inner: monad_evcap_event_iter,
    _phantom: PhantomData<(&'section (), D)>,
}

impl<'reader, 'section, D> EventCaptureEventIter<'reader, 'section, D>
where
    D: EventDecoder,
{
    pub(super) fn new(
        reader: &'reader monad_evcap_reader,
        event_section: &monad_evcap_event_section,
    ) -> Self {
        let inner = monad_evcap_event_section_open_iterator(event_section);

        Self {
            reader,
            inner,
            _phantom: PhantomData,
        }
    }

    pub fn next(
        &mut self,
    ) -> EventCaptureNextResult<EventDescriptor<EventCapturePayload<'reader>, D>> {
        let (result, c_event_descriptor, payload): (
            monad_evcap_read_result,
            Option<&'reader monad_event_descriptor>,
            Option<&'reader [u8]>,
        ) = unsafe { monad_evcap_event_iter_next(&mut self.inner) };

        match result {
            ffi::MONAD_EVCAP_READ_SUCCESS => {
                let raw_event_descriptor: RawEventDescriptor<&'reader [u8]> =
                    RawEventDescriptor::new(*c_event_descriptor.unwrap(), &payload.unwrap());

                EventCaptureNextResult::Success(EventDescriptor::new(raw_event_descriptor))
            }
            ffi::MONAD_EVCAP_READ_END => EventCaptureNextResult::End,
            ffi::MONAD_EVCAP_READ_NO_SEQNO => EventCaptureNextResult::NoSeqno,
            _ => unimplemented!(),
        }
    }
}

pub struct EventCapturePayload<'reader> {
    _phantom: PhantomData<&'reader [u8]>,
}

impl<'reader> EventDescriptorRead for EventCapturePayload<'reader> {
    type Raw = &'reader [u8];

    type Result<T> = T;

    fn try_filter_map<'buf, T>(
        this: &RawEventDescriptor<Self::Raw>,
        f: impl FnOnce(RawEventDescriptorInfo, &[u8]) -> T,
    ) -> Self::Result<T> {
        f(this.info(), this.with_inner().1)
    }
}
