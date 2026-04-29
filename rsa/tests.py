from rsa import *






def test1():
    p,q = distant_random_primes(1024)
    pr, pu = rsa_keys((p,q))
    text = 123456
    cipher_text = encrypt(text,pu)
    de_text = decrypt(cipher_text,(pr.d,pr.n))
    print(cipher_text)
    print(de_text)
    print(text==de_text)
    my_signature = sign(text,pr)
    print(my_signature)
    print(verify(text,my_signature,pu))

def test2():
    p,q = distant_random_primes(1024)
    pr, pu = rsa_keys((p,q))
    key_bytes = dump_public_key(pu)
    print(key_bytes)
    pu2 = load_public_key(key_bytes)
    print(f"pu2: {pu2} \n pu:{pu}")
    print(f"match: {pu == pu2}")
    text = b"hello my name is gil and i like lego"
    cipher = encrypt_bytes(text,pu)
    print(cipher.hex())
    de_text = decrypt_bytes(cipher,pr)
    print(de_text,f"\nmatch: {de_text == text}")
    signed = sign_bytes(text,pr)
    print(signed.hex())
    print(verify_all(signed,text,pu))

def test3():
    p, q = distant_random_primes(1024)
    pr1, pu1 = rsa_keys((p, q))
    p, q = distant_random_primes(1024)
    pr2, pu2 = rsa_keys((p, q))
    rsa1 = RSA(pu1,pr1)
    pu1_dump = rsa1.dump_my_public_key()
    rsa2 = RSA(pu2,pr2)
    pu2_dump = rsa2.dump_my_public_key()
    rsa1.load_peer_public_key(pu2_dump)
    rsa2.load_peer_public_key(pu1_dump)
    print(f"match 1->2:{rsa1.peer_public_key == rsa2.my_public_key}")
    print(f"match 2->1:{rsa2.peer_public_key == rsa1.my_public_key}")
    msg1 = rsa1.send(b"hello", b"this is verification")
    print(rsa2.receive(msg1))

def server_test():
    server = socket.socket()
    server.bind(("10.0.0.9",6666))
    server.listen()
    client = server.accept()[0]
    p,q = distant_random_primes(1024)
    pr, pu = rsa_keys((p,q))
    rsa = RSA(my_public_key=pu,my_private_key=pr)
    client_key = client.recv(1024)
    rsa.load_peer_public_key(client_key)
    client.send(rsa.dump_my_public_key())
    while True:
        msg = receiver(client)
        print(msg)
        print(rsa.receive(msg))
        response = input("what do you want to say back?")
        client.send(message_creator(response,rsa))

def client_test():
    client = socket.socket()
    client.connect(("10.0.0.13",5555))
    p,q = distant_random_primes(1024)
    pr, pu = rsa_keys((p,q))
    rsa = RSA(my_public_key=pu,my_private_key=pr)
    client.send(rsa.dump_my_public_key())
    client_key = client.recv(1024)
    rsa.load_peer_public_key(client_key)
    while True:
        msg = input("enter message to server")
        client.send(message_creator(msg,rsa))
        response = receiver(client)
        print(rsa.receive(response))


def message_creator(msg:str, rsa:RSA) -> bytes:
    msg_bytes = rsa.send(msg.encode(), "this is verification".encode())
    data = struct.pack("I", len(msg_bytes)) + msg_bytes
    return data



def receiver(client:socket.socket) ->bytes:
    data = client.recv(4)
    size = struct.unpack("I", data)[0]
    if size == 0:
        return b""
    message = client.recv(4096)
    size -=4096
    while size>0:
        message += client.recv(4096)
        size-=4096
        time.sleep(0.01)
        time.sleep(0.01)
    return message

def main():
    test3()



if __name__ == '__main__':
    main()


