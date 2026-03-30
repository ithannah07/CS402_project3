"""TLS 1.3 client for Part 3."""

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
LOGGER = logging.getLogger("client_pt3")


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


# Trust the CA for server verification and present the client certificate
# so the server can authenticate this client.
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile=str(BASE_DIR / "ca.crt"))
context.load_cert_chain(
    certfile=str(BASE_DIR / "client.crt"),
    keyfile=str(BASE_DIR / "client.key"),
)
context.minimum_version = ssl.TLSVersion.TLSv1_3

with socket.create_connection((HOST, PORT)) as sock:
    # Wrap the TCP socket with TLS and verify the server as localhost.
    with context.wrap_socket(sock, server_hostname="localhost") as tls_sock:
        peer_cert = tls_sock.getpeercert()
        cipher_info = tls_sock.cipher()
        host, port = tls_sock.getpeername()
        # Log the negotiated TLS session after server verification succeeds.
        log_json(
            "tls_handshake_succeeded",
            peer={"host": host, "port": port},
            tls_version=tls_sock.version(),
            cipher_suite=cipher_info[0] if cipher_info else None,
            peer_subject=peer_cert.get("subject"),
        )

        # Send one JSON request to the server.
        request = {"command": "GET_TIME"}
        tls_sock.sendall(json.dumps(request).encode())

        # Receive the server's JSON response and log it.
        response = json.loads(tls_sock.recv(4096).decode())
        log_json("server_response_received", response=response)
