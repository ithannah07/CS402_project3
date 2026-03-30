"""Secure TLS Client for part 1"""

import socket
import ssl
import json

HOST = "127.0.0.1"
PORT = 8443

# Create a TLS context with default certificate verification settings
context = ssl.create_default_context()

# Load trusted certificate for server verification
context.load_verify_locations("server.crt")

with socket.create_connection((HOST, PORT)) as sock:
    
    # Wrap the TCP socket with TLS and verify the server's certificate
    with context.wrap_socket(sock, server_hostname="localhost") as TLS_secure_sock:
        print("TLS version:", TLS_secure_sock.version())
        print("Cipher suite:", TLS_secure_sock.cipher())

        request = {"command": "GET_TIME"}

        # Communicate with the server over TLS
        TLS_secure_sock.sendall(json.dumps(request).encode())

        response = TLS_secure_sock.recv(4096)
        print("Server Response:", response.decode())
