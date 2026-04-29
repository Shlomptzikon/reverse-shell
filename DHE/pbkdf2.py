from dataclasses import dataclass

from DHE.kdf2 import KDF2
@dataclass
class PBKDF2(KDF2):
    salt: bytes
    iterations: int

    def derive(self, counter: int) -> bytes:
        first = self.hash(self.key + self.salt + counter.to_bytes(4, "big"))
        second = first[:]
        for i in range(self.iterations):
            first = self.hash(first)
            second = bytes(a^b for a,b in zip(first,second))
        return second
