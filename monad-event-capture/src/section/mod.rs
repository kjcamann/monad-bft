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

use monad_event::EventDecoder;

pub use self::iter::{EventCaptureEventIter, EventCapturePayload, EventCaptureRawPayload};
use crate::ffi::{
    self, monad_evcap_event_section, monad_evcap_event_section_close,
    monad_evcap_event_section_open, monad_evcap_reader, monad_evcap_section_desc,
    monad_evcap_section_type,
};

mod iter;

/// The types of sections in an event capture file.
#[derive(Debug, PartialEq, Eq)]
pub enum EventCaptureSectionType {
    /// A section containing the schema hash of a content type used in an
    /// [`EventBundle`](EventCaptureSectionType::EventBundle) section.
    Schema,

    /// A section containing events.
    EventBundle,

    /// An indexing section used to speed up seeking operations on events in the
    /// [`EventCaptureSectionType::EventBundle`] section.
    SeqnoIndex,

    /// An indexing section of finalized block pointers for files with multiple blocks.
    PackIndex,
}

impl EventCaptureSectionType {
    /// Creates a new [`EventCaptureSectionType`] from the ffi type.
    pub fn new(c_section_type: monad_evcap_section_type) -> Option<Self> {
        Some(match c_section_type {
            ffi::MONAD_EVCAP_SECTION_SCHEMA => Self::Schema,
            ffi::MONAD_EVCAP_SECTION_EVENT_BUNDLE => Self::EventBundle,
            ffi::MONAD_EVCAP_SECTION_SEQNO_INDEX => Self::SeqnoIndex,
            ffi::MONAD_EVCAP_SECTION_PACK_INDEX => Self::PackIndex,
            _ => return None,
        })
    }

    /// Produces the ffi type corresponding to the [`EventCaptureSectionType`].
    pub fn c_section_type(&self) -> monad_evcap_section_type {
        match self {
            EventCaptureSectionType::Schema => ffi::MONAD_EVCAP_SECTION_SCHEMA,
            EventCaptureSectionType::EventBundle => ffi::MONAD_EVCAP_SECTION_EVENT_BUNDLE,
            EventCaptureSectionType::SeqnoIndex => ffi::MONAD_EVCAP_SECTION_SEQNO_INDEX,
            EventCaptureSectionType::PackIndex => ffi::MONAD_EVCAP_SECTION_PACK_INDEX,
        }
    }
}

/// The metadata for an event section.
pub struct EventCaptureSectionDescriptor<'reader> {
    reader: &'reader monad_evcap_reader,
    inner: &'reader monad_evcap_section_desc,
}

impl<'reader> EventCaptureSectionDescriptor<'reader> {
    pub(crate) fn new(
        reader: &'reader monad_evcap_reader,
        inner: &'reader monad_evcap_section_desc,
    ) -> Self {
        Self { reader, inner }
    }

    /// Produces the section type associated with this [`EventCaptureSectionDescriptor`].
    pub fn section_type(&self) -> Option<EventCaptureSectionType> {
        EventCaptureSectionType::new(self.inner.type_)
    }

    /// Attempts to create an [`EventCaptureEventSection`] from this
    /// [`EventCaptureSectionDescriptor`]. This method will fail if the section is not an event
    /// section.
    pub fn open_event_section<D: EventDecoder>(
        self,
    ) -> Result<EventCaptureEventSection<'reader, D>, String> {
        EventCaptureEventSection::new(self.reader, self.inner)
    }
}

/// An event section in an event capture file.
pub struct EventCaptureEventSection<'reader, D>
where
    D: EventDecoder,
{
    inner: monad_evcap_event_section,
    _phantom: PhantomData<(&'reader (), fn() -> D)>,
}

impl<'reader, D> EventCaptureEventSection<'reader, D>
where
    D: EventDecoder,
{
    fn new(
        reader: &'reader monad_evcap_reader,
        section_desc: &monad_evcap_section_desc,
    ) -> Result<Self, String> {
        let inner = monad_evcap_event_section_open(reader, section_desc)?;

        Ok(Self {
            inner,
            _phantom: PhantomData,
        })
    }

    /// Creates an iterator over the events in this event section.
    pub fn open_iterator<'section>(&'section self) -> EventCaptureEventIter<'section, D> {
        EventCaptureEventIter::new(&self.inner)
    }
}

impl<'reader, D> Drop for EventCaptureEventSection<'reader, D>
where
    D: EventDecoder,
{
    fn drop(&mut self) {
        unsafe { monad_evcap_event_section_close(&mut self.inner) };
    }
}

unsafe impl<'reader, D> Send for EventCaptureEventSection<'reader, D> where D: EventDecoder {}
unsafe impl<'reader, D> Sync for EventCaptureEventSection<'reader, D> where D: EventDecoder {}
