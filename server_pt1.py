import socket
import ssl
import json
import datetime
import logging

HOST = "127.0.0.1"
PORT = 8443

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Bind TCP Socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Secure server listening on {PORT}")

    conn, addr = sock.accept()
    print("Connection from", addr)

    with context.wrap_socket(conn, server_side=True) as TLS_secure_conn:
        print("TLS version:", TLS_secure_conn.version())
        print("Cipher suite:", TLS_secure_conn.cipher()
              )
    
        data = TLS_secure_conn.recv(4096)
        request = json.loads(data.decode())

        if request.get("command") == "GET_TIME":
            response = {"time": datetime.datetime.now(
                datetime.timezone.utc).isoformat()}
        else:
            response = {"error": "Unknown command"}

        TLS_secure_conn.sendall(json.dumps(response).encode())
