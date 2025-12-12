use std::path::PathBuf;

use itertools::Itertools;
use monad_event_capture::{
    EventCaptureEventIter, EventCaptureEventSection, EventCaptureFile, EventCaptureNextResult,
    EventCaptureReader, EventCaptureSectionType,
};
use monad_exec_events::{ExecEventDecoder, ExecutedBlockBuilder};
use polars::prelude::*;
use pyo3::prelude::*;
use pyo3_polars::{
    PyDataFrame, PySchema, error::PyPolarsErr, export::polars_arrow::array::FixedSizeBinaryArray,
};

#[pyclass]
pub struct CallFramesSource {
    reader: EventCaptureReader,
    state: Option<(
        EventCaptureEventSection<'static, ExecEventDecoder>,
        EventCaptureEventIter<'static, ExecEventDecoder>,
    )>,
    block_builder: ExecutedBlockBuilder,

    n_rows: Option<usize>,
}

impl Drop for CallFramesSource {
    fn drop(&mut self) {
        self.state.take();
    }
}

#[pymethods]
impl CallFramesSource {
    #[new]
    #[pyo3(signature = (path, n_rows))]
    fn new_source(path: PathBuf, n_rows: Option<usize>) -> Self {
        let reader = EventCaptureFile::open(path)
            .unwrap()
            .create_reader()
            .unwrap();

        Self {
            reader,
            state: None,
            block_builder: ExecutedBlockBuilder::new(true, false),

            n_rows,
        }
    }

    fn schema(&self) -> PySchema {
        let schema = [
            ("block_number", DataType::UInt64),
            ("block_hash", DataType::Array(Box::new(DataType::UInt8), 32)),
            //
            ("tx_index", DataType::UInt32),
            ("tx_hash", DataType::Array(Box::new(DataType::UInt8), 32)),
            //
            ("call_frame_index", DataType::UInt32),
            ("call_frame_depth", DataType::UInt64),
            ("call_frame_opcode", DataType::UInt8),
            //
            (
                "call_frame_caller",
                DataType::Array(Box::new(DataType::UInt8), 20),
            ),
            (
                "call_frame_call_target",
                DataType::Array(Box::new(DataType::UInt8), 20),
            ),
        ]
        .into_iter()
        .map(|(name, datatype)| Field::new(PlSmallStr::from_static(name), datatype))
        .collect::<Schema>();

        PySchema(Arc::new(schema))
    }

    fn next(&mut self) -> PyResult<Option<PyDataFrame>> {
        let mut columns = (
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
            Vec::default(),
        );

        'outer: loop {
            let event_iter = loop {
                match self.state.as_mut() {
                    Some((_, event_iter)) => break event_iter,
                    None => {
                        let Some(section_descriptor) = self
                            .reader
                            .next_section(Some(EventCaptureSectionType::EventBundle))
                        else {
                            break 'outer;
                        };

                        let event_section: EventCaptureEventSection<'_, ExecEventDecoder> =
                            section_descriptor.open_event_section().unwrap();
                        let event_section: EventCaptureEventSection<'static, ExecEventDecoder> =
                            unsafe { std::mem::transmute(event_section) };

                        let event_iter: EventCaptureEventIter<'_, ExecEventDecoder> =
                            event_section.open_iterator();
                        let event_iter: EventCaptureEventIter<'static, ExecEventDecoder> =
                            unsafe { std::mem::transmute(event_iter) };

                        self.state = Some((event_section, event_iter));
                    }
                }
            };

            loop {
                match event_iter.next_descriptor() {
                    EventCaptureNextResult::End => {
                        self.state = None;
                        break;
                    }
                    EventCaptureNextResult::NoSeqno => unimplemented!(),
                    EventCaptureNextResult::Success(event_descriptor) => {
                        let Some(block_result) = self
                            .block_builder
                            .process_event_descriptor(&event_descriptor)
                        else {
                            continue;
                        };

                        let block = block_result.unwrap();

                        for (txn_index, txn) in block.txns.into_iter().enumerate() {
                            let txn_call_frames = txn.call_frames.unwrap();

                            for txn_call_frame in txn_call_frames.into_vec() {
                                columns.0.push(block.start.eth_block_input.number);
                                columns.1.push(block.start.block_tag.id.bytes);

                                columns.2.push(txn_index as u32);
                                columns.3.push(txn.hash.bytes);

                                columns.4.push(txn_call_frame.call_frame.index);
                                columns.5.push(txn_call_frame.call_frame.depth);
                                columns.6.push(txn_call_frame.call_frame.opcode);

                                columns.7.push(txn_call_frame.call_frame.caller.bytes);
                                columns.8.push(txn_call_frame.call_frame.call_target.bytes);
                            }
                        }

                        if let Some(n_rows) = self.n_rows {
                            if columns.0.len() >= n_rows {
                                break;
                            }
                        }
                    }
                }
            }
        }

        if columns.0.is_empty() {
            return Ok(None);
        }

        let build_fixed32 = |name: &'static str, values: Vec<[u8; 32]>| {
            Series::from_arrow(
                PlSmallStr::from_static(name),
                Box::new(FixedSizeBinaryArray::from_slice(values)),
            )
            .unwrap()
        };

        let build_fixed20 = |name: &'static str, values: Vec<[u8; 20]>| {
            Series::from_arrow(
                PlSmallStr::from_static(name),
                Box::new(FixedSizeBinaryArray::from_slice(values)),
            )
            .unwrap()
        };

        let columns = vec![
            Series::new(PlSmallStr::from_static("block_number"), columns.0),
            build_fixed32("block_hash", columns.1),
            //
            Series::new(PlSmallStr::from_static("tx_index"), columns.2),
            build_fixed32("tx_hash", columns.3),
            //
            Series::new(PlSmallStr::from_static("call_frame_index"), columns.4),
            Series::new(PlSmallStr::from_static("call_frame_depth"), columns.5),
            Series::new(PlSmallStr::from_static("call_frame_opcode"), columns.6),
            //
            build_fixed20("call_frame_caller", columns.7),
            build_fixed20("call_frame_call_target", columns.8),
        ]
        .into_iter()
        .map(|series| series.into_column())
        .collect_vec();

        let df = DataFrame::new(columns).map_err(PyPolarsErr::from)?;

        Ok(Some(PyDataFrame(df)))
    }
}
