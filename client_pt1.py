import socket
import ssl
import json

HOST = "127.0.0.1"
PORT = 8443

context = ssl.create_default_context()
context.load_verify_locations("server.crt")

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname="localhost") as TLS_secure_sock:
        print("TLS version:", TLS_secure_sock.version())
        print("Cipher suite:", TLS_secure_sock.cipher())

        request = {"command": "GET_TIME"}
        TLS_secure_sock.sendall(json.dumps(request).encode())

        response = TLS_secure_sock.recv(4096)
        print("Server Response:", response.decode())
