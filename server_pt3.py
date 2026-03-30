"""TLS 1.3 server for Part 3."""

import datetime
import json
import logging
from pathlib import Path
import socket
import ssl

HOST = "127.0.0.1"
PORT = 8443
BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO, format="%(message)s")
LOGGER = logging.getLogger("server_pt3")


def log_json(event, **fields):
    """Write one JSON log entry."""
    LOGGER.info(
        json.dumps(
            {
                "timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "event": event,
                **fields,
            }
        )
    )


# Use the server certificate for identity, trust the CA, and require
# a client certificate for mutual TLS.
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile=str(BASE_DIR / "server.crt"),
    keyfile=str(BASE_DIR / "server.key"),
)
context.load_verify_locations(cafile=str(BASE_DIR / "ca.crt"))
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.verify_mode = ssl.CERT_REQUIRED

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Secure TLS 1.3 server listening on {PORT}")

    # Accept one client connection over TCP.
    conn, addr = sock.accept()
    with context.wrap_socket(conn, server_side=True) as tls_conn:
        peer_cert = tls_conn.getpeercert()
        cipher_info = tls_conn.cipher()
        # Log the negotiated TLS session after the handshake succeeds.
        log_json(
            "tls_handshake_succeeded",
            peer={"host": addr[0], "port": addr[1]},
            tls_version=tls_conn.version(),
            cipher_suite=cipher_info[0] if cipher_info else None,
            peer_subject=peer_cert.get("subject"),
        )

        # Read one JSON request from the client.
        request = json.loads(tls_conn.recv(4096).decode())
        if request.get("command") == "GET_TIME":
            # Return the current UTC time for the expected command.
            response = {
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        else:
            # Keep the fallback error response simple.
            response = {"error": "Unknown command"}

        # Send the response back through the TLS connection.
        tls_conn.sendall(json.dumps(response).encode())
