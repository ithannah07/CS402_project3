#!/bin/bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
openssl req -x509 -newkey rsa:2048 -keyout client.key -out client.crt -days 365 -nodes -subj "/CN=client"

# confirmed that no CA is needed. using manual self signed certs and keys without CA. This is much simpler. Added #!/bin/bash to run as a shell script.