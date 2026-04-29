from DHE.pbkdf2 import PBKDF2
from DHE.my_hmac import HMAC
import os
import hashlib
from dataclasses import dataclass
@dataclass
class PBKDF2HMAC(PBKDF2):
    def hash(self, data: bytes) -> bytes:
        return HMAC(self.algorithm, key=self.key, data=data).derive()


    def derive(self, counter: int) -> bytes:
        first = self.hash(self.salt + counter.to_bytes(4, "big"))
        second = first[:]
        for i in range(1,self.iterations):
            first = self.hash(first)
            second = bytes(a^b for a,b in zip(first,second))
        return second


def main():
    password = b"super_secret_password"
    salt = os.urandom(16)  # Generate a random salt
    iterations = 100000  # Recommended number of iterations
    key_length = 32  # Desired key length

    # Generate PBKDF2-HMAC key using SHA256
    derived_key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=key_length)
    my_bullshit = PBKDF2HMAC('sha256',password,key_length,salt,iterations).digest()
    print(f"Derived Key: {derived_key.hex()}")
    print(f"Derived Key: {my_bullshit.hex()}")
    print(f"match: {my_bullshit == derived_key}")


if __name__ == '__main__':
    main()