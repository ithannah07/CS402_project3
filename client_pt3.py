"""TLS 1.3 client with mutual TLS."""

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


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile=str(BASE_DIR / "ca.crt"))
context.load_cert_chain(
    certfile=str(BASE_DIR / "client.crt"),
    keyfile=str(BASE_DIR / "client.key"),
)
context.minimum_version = ssl.TLSVersion.TLSv1_3

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname="localhost") as tls_sock:
        peer_cert = tls_sock.getpeercert()
        cipher_info = tls_sock.cipher()
        host, port = tls_sock.getpeername()
        log_json(
            "tls_handshake_succeeded",
            peer={"host": host, "port": port},
            tls_version=tls_sock.version(),
            cipher_suite=cipher_info[0] if cipher_info else None,
            peer_subject=peer_cert.get("subject"),
        )

        request = {"command": "GET_TIME"}
        tls_sock.sendall(json.dumps(request).encode())

        response = json.loads(tls_sock.recv(4096).decode())
        log_json("server_response_received", response=response)
