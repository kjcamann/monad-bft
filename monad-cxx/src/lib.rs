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

use std::sync::Once;
use tracing::{event, Level};

#[repr(C)]
struct QuillLogEvent
{
    log_level: u8
}

// Called by quill, sent to tracing framework via the event! macro
extern "C" fn log_callback(pq: *const QuillLogEvent)
{
    let q = unsafe{ & *pq };
    match q.log_level {
        0..=2 => event!(Level::TRACE, "hi"),
        3 => event!(Level::DEBUG, "hi"),
        4 => event!(Level::INFO, "hi"),
        5 => event!(Level::WARN, "hi"),
        _ => event!(Level::ERROR, "hi"),
    };
}

extern "C" {
    fn monad_cxx_env_init_quill(cb: extern "C" fn(*const QuillLogEvent));
}

static QUILL_INIT: Once = Once::new();

pub fn init_quill_logging() {
    QUILL_INIT.call_once(|| {
        unsafe { monad_cxx_env_init_quill(log_callback) };
    });
}
