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

use monad_event_capture::EventCaptureNextResult;
use monad_event_ring::{EventNextResult, EventPayloadResult};

pub enum EventSourceNextResult<T> {
    Ok(T),

    NotReady,
    Gap,

    End,
    NoSeqno,
}

impl<T> EventSourceNextResult<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> EventSourceNextResult<U> {
        match self {
            EventSourceNextResult::Ok(value) => EventSourceNextResult::Ok(f(value)),
            EventSourceNextResult::NotReady => EventSourceNextResult::NotReady,
            EventSourceNextResult::Gap => EventSourceNextResult::Gap,
            EventSourceNextResult::End => EventSourceNextResult::End,
            EventSourceNextResult::NoSeqno => EventSourceNextResult::NoSeqno,
        }
    }
}

impl<T> From<EventNextResult<T>> for EventSourceNextResult<T> {
    fn from(value: EventNextResult<T>) -> Self {
        match value {
            EventNextResult::Ready(value) => Self::Ok(value),
            EventNextResult::NotReady => Self::NotReady,
            EventNextResult::Gap => Self::Gap,
        }
    }
}

impl<T> From<EventCaptureNextResult<T>> for EventSourceNextResult<T> {
    fn from(value: EventCaptureNextResult<T>) -> Self {
        match value {
            EventCaptureNextResult::Success(value) => Self::Ok(value),
            EventCaptureNextResult::End => Self::End,
            EventCaptureNextResult::NoSeqno => Self::NoSeqno,
        }
    }
}

pub enum EventSourceResult<T> {
    Ok(T),

    Expired,
}

impl<T> EventSourceResult<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> EventSourceResult<U> {
        match self {
            EventSourceResult::Ok(value) => EventSourceResult::Ok(f(value)),
            EventSourceResult::Expired => EventSourceResult::Expired,
        }
    }
}

impl<T> From<EventPayloadResult<T>> for EventSourceResult<T> {
    fn from(value: EventPayloadResult<T>) -> Self {
        match value {
            EventPayloadResult::Ready(value) => Self::Ok(value),
            EventPayloadResult::Expired => Self::Expired,
        }
    }
}
