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

use monad_event::{EventDecoder, EventDescriptor};
use monad_event_capture::EventCaptureEventIter;
use monad_event_ring::EventReader;

use crate::{EventSourceNextResult, EventSourceRead, RawEventSourceRead};

/// A generic event iterator.
pub enum EventSourceIter<'source, D>
where
    D: EventDecoder,
{
    /// TODO
    Capture(EventCaptureEventIter<'source, D>),
    /// TODO
    Ring(EventReader<'source, D>),
}

impl<'source, D> EventSourceIter<'source, D>
where
    D: EventDecoder,
{
    /// TODO
    pub fn try_next(
        &mut self,
    ) -> EventSourceNextResult<EventDescriptor<EventSourceRead<'source>, D>> {
        match self {
            EventSourceIter::Capture(event_iter) => {
                EventSourceNextResult::from(event_iter.next_descriptor())
                    .map(|event_descriptor| event_descriptor.map(RawEventSourceRead::Capture))
            }
            EventSourceIter::Ring(event_reader) => EventSourceNextResult::from(
                event_reader
                    .next_descriptor()
                    .map(|event_descriptor| event_descriptor.map(RawEventSourceRead::Ring)),
            ),
        }
    }
}
