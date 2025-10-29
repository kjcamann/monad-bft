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

pub use self::raw::{RawEventDescriptor, RawEventDescriptorInfo};
use crate::EventDecoder;

mod raw;

/// The metadata for an event.
#[derive(Debug)]
pub struct EventDescriptor<B, D>
where
    B: EventDescriptorRead,
    D: EventDecoder,
{
    raw: RawEventDescriptor<B::Raw>,
    _phantom: PhantomData<D>,
}

impl<B, D> EventDescriptor<B, D>
where
    B: EventDescriptorRead,
    D: EventDecoder,
{
    /// TODO: docs
    pub fn new(raw: RawEventDescriptor<B::Raw>) -> Self {
        Self {
            raw,
            _phantom: PhantomData,
        }
    }

    /// Produces the [`EventDescriptorInfo`] associated with this descriptor.
    pub fn info(&self) -> EventDescriptorInfo<D> {
        EventDescriptorInfo::new(self.raw.info())
    }

    /// Attempts to read the payload associated with this event descriptor as the associated
    /// [`T::Event`](EventDecoder::Event) type.
    pub fn try_read(&self) -> B::Result<D::Event> {
        B::try_filter_map(&self.raw, |raw_info, bytes| {
            let info = EventDescriptorInfo::new(raw_info);

            let event_ref = D::raw_to_event_ref(info, bytes);

            D::event_ref_to_event(event_ref)
        })
    }

    /// Attempts to selectively read the payload associated with this event descriptor to a
    /// user-specified type.
    ///
    /// This function enables a zero-copy API by allowing downstream consumers to `filter_map` the
    /// [`D::EventRef`](EventDecoder::EventRef) type which is a zero-copy view of the underlying
    /// bytes.
    ///
    /// <div class="warning">
    ///
    /// The `filter_map` function `f` **must** be a pure function and thus side-effect free. During
    /// `f`'s execution, it is possible for the underlying paylod bytes to be partially or
    /// completely overwritten which invalidates the zero-copy
    /// [`D::EventRef`](EventDecoder::EventRef). In this case, the result of the `filter_map` must
    /// be discarded, which is expressed through the [`EventPayloadResult::Expired`] variant. This
    /// requirement is further hinted at through the type definition for `f` which is intentionally
    /// a function pointer instead of a closure to avoid accidentally setting state outside the
    /// `filter_map`. Downstream consumers should **not** attempt to circumvent this behavior.
    ///
    /// </div>
    pub fn try_filter_map<R: 'static>(
        &self,
        f: fn(event_ref: D::EventRef<'_>) -> Option<R>,
    ) -> B::Result<Option<R>> {
        B::try_filter_map(&self.raw, |raw_info, bytes| {
            let info = EventDescriptorInfo::new(raw_info);

            let event_ref = D::raw_to_event_ref(info, bytes);

            f(event_ref)
        })
    }

    /// Attempts to selectively read the payload byte slice associated with this event descriptor to
    /// a user-specified type.
    ///
    /// This function enables a zero-copy API by providing downstream consumers the underlying
    /// payload byte slice. This method should **not** be used unless you explicitly need to work
    /// at a byte-level view.
    ///
    /// <div class="warning">
    ///
    /// See [`try_filter_map`](EventDescriptor::try_filter_map) for important semantics about `f`.
    ///
    /// </div>
    pub fn try_filter_map_raw<R: 'static>(
        &self,
        f: fn(info: EventDescriptorInfo<D>, payload_bytes: &[u8]) -> Option<R>,
    ) -> B::Result<Option<R>> {
        B::try_filter_map(&self.raw, |raw_info, bytes| {
            let info = EventDescriptorInfo::new(raw_info);

            f(info, bytes)
        })
    }
}

/// TODO: docs
pub trait EventDescriptorRead
where
    Self: Sized,
{
    /// TODO: docs
    type Raw;

    /// TODO: docs
    type Result<T>;

    /// TODO: docs
    fn try_filter_map<T>(
        this: &RawEventDescriptor<Self::Raw>,
        f: impl FnOnce(RawEventDescriptorInfo, &[u8]) -> T,
    ) -> Self::Result<T>;
}

/// Information associated with an event descriptor.
pub struct EventDescriptorInfo<D>
where
    D: EventDecoder,
{
    /// Sequence number used to check liveness / detect gapping.
    pub seqno: u64,

    /// Enables distinguishing between variadic inner event types.
    ///
    /// See [`EventDecoder`] for more details.
    pub event_type: u16,

    /// The time at which the event was recorded.
    pub record_epoch_nanos: u64,

    /// The flow information associated with this event descriptor,
    ///
    /// See [`EventDecoder::FlowInfo`] for more details.
    pub flow_info: D::FlowInfo,
}

impl<D> EventDescriptorInfo<D>
where
    D: EventDecoder,
{
    /// TODO: docs
    pub fn new(raw: RawEventDescriptorInfo) -> Self {
        Self {
            seqno: raw.seqno,
            event_type: raw.event_type,
            record_epoch_nanos: raw.record_epoch_nanos,
            flow_info: D::transmute_flow_info(raw.content_ext),
        }
    }
}
