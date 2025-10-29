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

/// The result of attempting to perform a seeking operation on an
/// [`EventCaptureReader`](crate::EventCaptureReader).
pub enum EventCaptureNextResult<T> {
    /// The seeked event is available and produced through `T`.
    Success(T),

    /// There are no more events.
    End,

    /// The event capture file does not have a
    /// [`SeqnoIndex`](crate::EventCaptureSectionType::SeqnoIndex) section.
    NoSeqno,
}
