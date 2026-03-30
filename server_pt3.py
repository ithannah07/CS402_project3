import socket
import ssl
import json
import logging
import datetime

HOST = "127.0.0.1"
PORT = 8443
logging.basicConfig(level=logging.INFO)

# Create TLS context that presents the server cert and requires a client cert
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")    # server's identity
context.load_verify_locations("client.crt") # trust client's self-signed cert
context.verify_mode = ssl.CERT_REQUIRED     # require client cert (mutual TLS)
context.minimum_version = ssl.TLSVersion.TLSv1_3    # enforce TLS 1.3 minimum

# Bind TCP socket and wait for a connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Secure server listening on {PORT}")
    
    conn, addr = sock.accept()
    print("Connection from", addr)
    
    # Upgrade the connection to TLS
    with context.wrap_socket(conn, server_side=True) as TLS_secure_conn:
        # Log TLS session details as structured JSON
        logging.info(json.dumps({
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tls_version":  TLS_secure_conn.version(),
            "cipher_suite": TLS_secure_conn.cipher()[0],
            "client_ip":    addr[0]
        }))

        # Receive and decode the client's request
        data = TLS_secure_conn.recv(4096)
        request = json.loads(data.decode()) # parse JSON

        # Build response based on command
        if request.get("command") == "GET_TIME":
            response = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        else:
            response = {"error": "Unknown command"}

        TLS_secure_conn.sendall(json.dumps(response).encode())  # Send response
