"""Secure TLS Client for part 3"""

import socket
import ssl
import json
import logging
import datetime

HOST = "127.0.0.1"
PORT = 8443
logging.basicConfig(level=logging.INFO)

# Create TLS context that verifies the server's certificate
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations("server.crt")                            # trust server's self-signed cert
context.load_cert_chain(certfile="client.crt", keyfile="client.key")  # present client cert (mutual TLS)
context.minimum_version = ssl.TLSVersion.TLSv1_3                      # enforce TLS 1.3 minimum

# Open a TCP connection and upgrade to TLS
with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname="localhost") as TLS_secure_sock:
        # Log TLS session details as structured JSON
        logging.info(json.dumps({
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tls_version":  TLS_secure_sock.version(),
            "cipher_suite": TLS_secure_sock.cipher()[0],
            "server_ip":    TLS_secure_sock.getpeername()[0]
        }))

        # Send request and receive response
        request = {"command": "GET_TIME"}
        
        # Communicate with the server over TLS
        TLS_secure_sock.sendall(json.dumps(request).encode())

        response = TLS_secure_sock.recv(4096)
        print("Server Response:", response.decode())
