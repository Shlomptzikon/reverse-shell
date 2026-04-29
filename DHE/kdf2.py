from DHE.kdf import KDF
from dataclasses import dataclass


@dataclass
class KDF2(KDF):
    def derive(self, counter: int) -> bytes:
        return self.hash(self.key+counter.to_bytes(4, "big"))
    