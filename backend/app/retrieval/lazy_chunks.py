"""Byte-bounded source cache for a pinned persistent intelligence snapshot."""

from collections import OrderedDict
from collections.abc import Mapping


class LazyChunks(Mapping):
    def __init__(self, index, *, max_bytes=2_097_152):
        self.index = index
        self.max_bytes = max_bytes
        self.cache = OrderedDict()
        self.cache_bytes = 0

    def __getitem__(self, chunk_id):
        if chunk_id in self.cache:
            self.cache.move_to_end(chunk_id)
            return self.cache[chunk_id]
        chunk = self.index.load_chunk(chunk_id)
        if chunk is None:
            raise KeyError(chunk_id)
        size = len(chunk.content.encode("utf-8"))
        while self.cache and self.cache_bytes + size > self.max_bytes:
            _, removed = self.cache.popitem(last=False)
            self.cache_bytes -= len(removed.content.encode("utf-8"))
        if size <= self.max_bytes:
            self.cache[chunk_id] = chunk
            self.cache_bytes += size
        return chunk

    def __iter__(self):
        # Only the active working set can be enumerated. Discovery of source
        # must go through a bounded persistent query, never Mapping.values().
        return iter(tuple(self.cache))

    def __len__(self):
        return len(self.cache)
