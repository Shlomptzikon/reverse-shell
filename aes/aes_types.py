from symtable import Class

from aes.functions import aes128_decrypt, aes128_encrypt
import os

def split_chunks(data:bytes, size: int = 16):
    for i in range(0,len(data),size):
        yield data[i:i+size]

class PKCS7:

    def pad(self, data:bytes, size:int = 16) ->bytes:
        missing = size - (len(data) % size)
        padding = bytes([missing]) * missing
        return data + padding

    def unpad(self, data:bytes, size:int = 16) ->bytes:
        if not data or len(data) % size != 0:
            raise ValueError("invalid padded data length")
        missing = data[-1]
        if missing < 1 or missing > size:
            raise ValueError("Invalid padding length")
        return data[:-missing]
    

class ECB:
    def __init__(self,key:bytes):
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes long")
        self.key = key
        self.p = PKCS7()

    def encrypt(self,plaintext: bytes) -> bytes:
        padded = self.p.pad(plaintext,16)
        ciphertext = b""
        for chunk in split_chunks(padded,16):
            ciphertext+= aes128_encrypt(key=self.key,plaintext=chunk)
        return ciphertext

    def decrypt(self,ciphertext: bytes) -> bytes:
        plaintext = b""
        for chunk in split_chunks(ciphertext,16):
            plaintext += aes128_decrypt(self.key,chunk)
        return self.p.unpad(plaintext,16)




class CBC:
    def __init__(self,key:bytes, iv:bytes):
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes long")
        self.key = key
        if len(iv) != 16:
            raise ValueError("AES iv must be 16 bytes long")
        self.iv = iv
        self.p = PKCS7()

    def encrypt(self, plaintext:bytes) -> bytes:
        padded = self.p.pad(plaintext,16)
        ciphertext = b""
        prev = self.iv
        for chunk in split_chunks(padded,16):
            xored = bytes(a ^ b for a, b in zip(prev, chunk))
            encrypted = aes128_encrypt(self.key,xored)
            ciphertext +=encrypted
            prev = encrypted
        return ciphertext

    def decrypt(self,ciphertext:bytes) ->bytes:
        prev = self.iv
        plaintext = b""
        for chunk in split_chunks(ciphertext,16):
            decrypted = aes128_decrypt(self.key,chunk)
            plaintext += bytes(a ^ b for a, b in zip(prev, decrypted))
            prev = chunk
        return self.p.unpad(plaintext,16)


class CFB:

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes long")
        self.key = key
        if len(iv) != 16:
            raise ValueError("AES iv must be 16 bytes long")
        self.iv = iv
        self.p = PKCS7()

    def encrypt(self, plaintext:bytes) ->bytes:
        padded = self.p.pad(plaintext)
        prev = self.iv
        ciphertext =b""
        for chunk in split_chunks(padded,16):
            encrypted = aes128_encrypt(self.key,prev)
            xored = bytes(a ^ b for a, b in zip(encrypted, chunk))
            prev = xored
            ciphertext +=xored
        return ciphertext


    def decrypt(self, ciphertext:bytes) ->bytes:
        prev = self.iv
        plaintext = b""
        for chunk in split_chunks(ciphertext, 16):
            decrypted = aes128_encrypt(self.key,prev)
            prev = chunk
            plaintext += bytes(a ^ b for a, b in zip(chunk, decrypted))
        return self.p.unpad(plaintext,16)




class OFB:
    def __init__(self,key:bytes, iv:bytes):
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes long")
        self.key = key
        if len(iv) != 16:
            raise ValueError("AES iv must be 16 bytes long")
        self.iv = iv
        self.p = PKCS7()


    def encrypt(self, plaintext:bytes) -> bytes:
        padded = self.p.pad(plaintext,16)
        ciphertext = b""
        prev = self.iv
        for chunk in split_chunks(padded,16):
            encrypted = aes128_encrypt(self.key, prev)
            prev = encrypted
            ciphertext += bytes(a ^ b for a, b in zip(chunk, encrypted))
        return ciphertext



    def decrypt(self, ciphertext: bytes) -> bytes:
        prev = self.iv
        plaintext = b""
        for chunk in split_chunks(ciphertext, 16):
            decrypted = aes128_encrypt(self.key, prev)
            prev = decrypted
            plaintext += bytes(a ^ b for a, b in zip(chunk, decrypted))

        return self.p.unpad(plaintext, 16)

class CTR:
    def __init__(self,key:bytes, nonce:bytes):
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes long")
        self.key = key
        if len(nonce) != 8:
            raise ValueError("AES nonce must be 8 bytes long")
        self.nonce = nonce
        self.p = PKCS7()

    def encrypt(self, plaintext:bytes) ->bytes:
        ciphertext = b""
        padded = self.p.pad(plaintext,16)
        counter =0
        for chunk in split_chunks(padded,16):
            counter_block = self.nonce + counter.to_bytes(8, "big")
            encrypted = aes128_encrypt(self.key,counter_block)
            ciphertext += bytes(a ^ b for a, b in zip(chunk, encrypted))
            counter+=1
        return ciphertext

    def decrypt(self, ciphertext:bytes) -> bytes:
        plaintext = b""
        counter = 0
        for chunk in split_chunks(ciphertext,16):
            counter_block = self.nonce + counter.to_bytes(8, "big")
            encrypted = aes128_encrypt(self.key,counter_block)
            plaintext += bytes(a ^ b for a, b in zip(chunk, encrypted))
            counter+=1
        return self.p.unpad(plaintext,16)






def main():
    h = b"hello sfefrwrwer"
    pkcs7 = PKCS7()
    h_padded = pkcs7.pad(h)
    h_unpadded  = pkcs7.unpad(h_padded)
    print(h_padded)
    print(h_unpadded)
    ecb = CTR(os.urandom(16),os.urandom(8))
    c = ecb.encrypt(h)
    print(c)
    print(ecb.decrypt(c))


if __name__ == '__main__':
    main()
    
    

