# Project 3 Part 3 Notes

`server_pt3.py`

- runs a TCP server on `127.0.0.1:8443`
- wraps the accepted socket with TLS
- enforces TLS 1.3 minimum
- requires a client certificate signed by `ca.crt`
- logs the negotiated TLS version, cipher suite, and client certificate subject
- returns the current UTC time for `{"command": "GET_TIME"}`

`client_pt3.py`

- connects to `127.0.0.1:8443`
- verifies the server certificate using `ca.crt`
- presents `client.crt` and `client.key` for mutual TLS
- enforces TLS 1.3 minimum
- logs the negotiated TLS version, cipher suite, and server certificate subject

`gen_cert.sh`
gotiated TLS version, cipher suite, and server certificate subject

`gen_cert.sh`

- creates a local CA
- creates a server certificate signed by that CA
- creates a client certificate signed by that CA
- adds `serverAuth`, `clientAuth`, and SAN settings used by the current setup

## Questions to ask the professor

### About `gen_cert.sh`

1. Do you expect us to generate a local CA plus separate server/client certificates, or is a simpler certificate setup acceptable as long as mutual TLS works?
2. Is it okay to include certificate extensions like `serverAuth`, `clientAuth`, and `subjectAltName`, or do you want the certificate generation kept as close as possible to the single-command example from Part 1?

### About `server_pt3.py`

1. For "structured logging of TLS session details," is logging `tls_version`, `cipher_suite`, and `peer_subject` enough?
2. For client authentication, is using `ssl.CERT_REQUIRED` on the server side the expected implementation?

### About `client_pt3.py`

1. Should the client verify the server using `ca.crt` plus `server_hostname="localhost"`?
2. Is logging the TLS session plus the final server response enough for the client side?

## My current assumptions

- TLS 1.3 minimum is required on both client and server
- mutual TLS means the server must require and verify a client certificate
- structured logging only needs to show key session details, not every possible field
