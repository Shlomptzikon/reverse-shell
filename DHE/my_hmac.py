import hashlib

class HMAC:
    def __init__(self, algorithm: str, data: bytes, key: bytes, size: int = 64):
        self.algorithm = algorithm
        self.data = data
        self.key = key
        self.size = size

    def hash(self, data: bytes) -> bytes:
        gen = hashlib.new(self.algorithm, data)
        return gen.digest()

    def sized_key(self) -> bytes:
        key = self.key
        if len(key) > self.size:
            key = self.hash(key)
        if len(key) < self.size:
            key += b'\x00' * (self.size - len(key))
        return key

    def derive(self) -> bytes:
        key = self.sized_key()
        k1 = bytes(a ^ b for a, b in zip(key, bytes([0x36] * self.size)))
        k2 = bytes(a ^ b for a, b in zip(key, bytes([0x5c] * self.size)))
        inner = self.hash(k1 + self.data)
        code = self.hash(k2 + inner)

        return code






