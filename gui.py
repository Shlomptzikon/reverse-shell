import cv2
import numpy as np
import mss
import socket
import struct


server_ip = "10.0.0.18"  # listen on all interfaces
server_port = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((server_ip, server_port))
sock.listen(1)
print(f"Listening on {server_ip}:{server_port} ...")
conn, addr = sock.accept()
print(f"Connection from {addr}")

with mss.mss() as sct:
    monitor = sct.monitors[1]  # capture main screen

    while True:
        # Capture screen
        frame = np.array(sct.grab(monitor))
        frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)

        # Encode frame as JPEG
        encoded, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 50])

        # Send size first, then data
        data = buffer.tobytes()
        conn.sendall(struct.pack(">L", len(data)) + data)
