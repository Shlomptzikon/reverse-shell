import hashlib
from dataclasses import dataclass


@dataclass
class KDF:
    algorithm: str
    key: bytes
    size: int

    def hash(self, data: bytes) -> bytes:
        gen = hashlib.new(self.algorithm, data)
        return gen.digest()

    def derive(self, counter: int) -> bytes:
        return self.hash(self.key)

    def digest(self) -> bytes:
        blocks = []
        counter, total_size = 1, 0

        while total_size < self.size:
            blocks.append(self.derive(counter))
            total_size += len(blocks[-1])
            counter += 1

        return b"".join(blocks)[:self.size]
