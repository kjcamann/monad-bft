from typing import Any, Iterator
from polars.io.plugins import register_io_source

import polars as pl

from .monad_exec_events import BlockArchive

class BlockArchiveScanner:
    def __init__(self, path: str) -> BlockArchive:
        self.inner = BlockArchive(path)

    def slot_updates(self, block_start: int, block_end: int):
        return _scan(self.inner.create_slot_update_scanner(block_start, block_end))

    def block_performance(self, block_start: int, block_end: int):
        return _scan(self.inner.create_block_performance_scanner(block_start, block_end))

    def tx_performance(self, block_start: int, block_end: int):
        return _scan(self.inner.create_tx_performance_scanner(block_start, block_end))

    def tx_gas(self, block_start: int, block_end: int):
        return _scan(self.inner.create_tx_gas_scanner(block_start, block_end))

    def tx_header(self, block_start: int, block_end: int):
        return _scan(self.inner.create_tx_header_scanner(block_start, block_end))
    
def _scan(scanner):
    def source_generator(
        with_columns: list[str] | None,
        predicate: pl.Expr | None,
        n_rows: int | None,
        batch_size: int | None,
    ) -> Iterator[pl.DataFrame]:
        max_rows = n_rows

        if batch_size is not None:
            if max_rows is not None:
                max_rows = min(max_rows, batch_size)
            else:
                max_rows = batch_size
        
        processor = scanner.create_processor()

        if max_rows is not None:
            processor.set_max_rows(max_rows)

        if with_columns is not None:
            processor.set_with_columns(with_columns)

        if predicate is not None:
            processor.set_predicate(predicate)

        while (out := processor.next()) is not None:
            yield out

    return register_io_source(
        io_source=source_generator,
        schema=scanner.schema()
    )
