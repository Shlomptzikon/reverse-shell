import concurrent.futures
import math
import random
from dataclasses import dataclass
import json
import base64
from sympy import isprime
@dataclass
class PublicKey:
    n: int
    e: int


@dataclass
class PrivateKey:
    n: int
    d: int


def get_prime(size:int) -> int:
    candidate = random.randrange(2 ** (size - 1), 2 ** size)
    while not isprime(candidate):
        candidate = random.randrange(2 ** (size - 1), 2 ** size)
    return candidate

def distant_random_primes(size:int) -> tuple[int,int]:
    half = size // 2
    half_and_half: int = ((1 << half) - 1) << (size - half)
    p = get_prime(size)
    q = get_prime(size)
    while p & half_and_half == q & half_and_half:
        q = get_prime(size)
    return p,q


def rsa_keys(primes: tuple[int, int]) -> tuple[PrivateKey, PublicKey]:
    n = primes[0] * primes[1]
    phi = (primes[0] - 1) * (primes[1] - 1)
    e = 65537
    if math.gcd(e,phi) != 1:
        e = 3
        while math.gcd(e,phi) !=1:
            e+=2
    d = pow(e, -1, phi)
    return PrivateKey(n,d),PublicKey(n,e)


def encrypt(data: int, key: PublicKey) -> int:
    return pow(data, key.e, key.n)

def decrypt(data: int, key: PrivateKey) -> int:
    return pow(data, key.d, key.n)


def sign(data: int, key: PrivateKey) -> int:
    return pow(data, key.d, key.n)

def verify(data: int, signature: int, key: PublicKey) -> bool:
    return data == pow(signature, key.e, key.n)




def bytes_to_list(data: bytes,n:int) -> list[int]:
    chunk_len = (n.bit_length()+7)//8 - 1
    result:list[int] = []
    for i in range(0,len(data),chunk_len):
        chunk = data[i : i+chunk_len]
        result.append(int.from_bytes(chunk, byteorder='big'))
    return result

def list_to_bytes(data: list[int]) -> bytes:

    chunk_list: list[bytes] = []
    for temp in data:
        hex_string = hex(temp)[2:]
        chunk_list.append(bytes.fromhex(hex_string.zfill(len(hex_string) + len(hex_string) % 2))
)
    return b''.join(chunk_list)


def sign_bytes(data: bytes, key: PrivateKey) -> bytes:
    temp = bytes_to_list(data,key.n)
    signed = [sign(item, key) for item in temp]
    json_str = json.dumps(signed)
    return base64.urlsafe_b64encode(json_str.encode('utf-8'))

def encrypt_bytes(data: bytes, key: PublicKey) -> bytes:
    temp = bytes_to_list(data,key.n)
    encrypted = [encrypt(item,key) for item in temp]
    json_str = json.dumps(encrypted)
    return base64.urlsafe_b64encode(json_str.encode('utf-8'))

def verify_all(signed_bytes: bytes, original_bytes: bytes, key: PublicKey) -> bool:
    json_bytes = base64.urlsafe_b64decode(signed_bytes)
    signed_list = json.loads(json_bytes.decode('utf-8'))
    original_list = bytes_to_list(original_bytes,key.n)
    for original, signed in zip(original_list, signed_list):
        if not verify(original,signed,key):
            return False
    return True

def decrypt_bytes(encrypted: bytes, key: PrivateKey) -> bytes:
    json_bytes = base64.urlsafe_b64decode(encrypted)
    encrypted_list = json.loads(json_bytes.decode('utf-8'))
    decrypted_list = [decrypt(item, key) for item in encrypted_list]
    return list_to_bytes(decrypted_list)


def dump_public_key(key:PublicKey) -> bytes:
    dict_key:dict[str:int] = {"n":key.n,"e":key.e}
    json_str = json.dumps(dict_key)
    return base64.urlsafe_b64encode(json_str.encode('utf-8'))

def load_public_key(decoded_key:bytes) -> PublicKey:
    json_bytes = base64.urlsafe_b64decode(decoded_key)
    dict_key = json.loads(json_bytes.decode('utf-8'))
    return PublicKey(dict_key["n"],dict_key["e"])



@dataclass
class RSA:
    my_public_key: PublicKey
    my_private_key: PrivateKey
    peer_public_key: PublicKey = None


    def dump_my_public_key(self) -> dict[str:int]:
        return dump_public_key(self.my_public_key)

    def load_peer_public_key(self, key_bytes:bytes):
        self.peer_public_key = load_public_key(key_bytes)

    def send(self, send_data:bytes, sign_data:bytes = None) -> bytes:
        send_data_encoded = base64.urlsafe_b64encode(send_data).decode()
        if sign_data:
            sign_data_encoded = base64.urlsafe_b64encode(sign_data).decode()
            signed = sign_bytes(sign_data,self.my_private_key).decode()
            data_dict: dict[str:bytes] = {"send_data": send_data_encoded, "sign_data": sign_data_encoded, "signed_data": signed}
        else:
            data_dict = {"send_data": send_data_encoded}
        data_bytes =  json.dumps(data_dict).encode('utf-8')
        return encrypt_bytes(data_bytes,self.peer_public_key)

    def receive(self, encrypted_data: bytes, verify: bool = True) -> str:
        data = decrypt_bytes(encrypted_data,self.my_private_key)
        dict_data:dict[str:bytes] = json.loads(data.decode('utf-8'))
        if verify:
            sign_data = base64.urlsafe_b64decode(dict_data["sign_data"])
            signed_data = dict_data["signed_data"]
            if verify_all(signed_data,sign_data,self.peer_public_key):
                return base64.urlsafe_b64decode(dict_data["send_data"]).decode()
            else:
                return "didn't pass verification"
        return base64.urlsafe_b64decode(dict_data["send_data"]).decode()