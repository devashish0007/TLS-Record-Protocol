
# Assignment  3: TLS Record Protocol

There will be two entities: the server (S) and the client (C). Assume that both entities already have their
certificates signed by the CA.

To start with, the client will contact the server; then, mutual authentication and initial key establishment
will be done as shown below. (The TLS Handshake protocol is not required). At the end of the initial
exchange, the client and server will have the 48-byte Pre-Master Secret (Kp).

C -> S: 601 | clientName | clientCertificate

(S verifies the client’s certificate using the CA’s public key.)

S -> C: 602 | serverName | serverCertificate

(C verifies the server’s certificate using the CA’s public key.)

(Next, C generates a pre-master secret (K_p) and encrypts this key
using S’s Public Key)


After the above initial authentication dialog, the client will send messages to retrieve files from the server.
The server will have several html files in its directory – these should be correctly-formatted and displayable
in a browser (Firefox, Chrome, etc.) running at the Client.
C -> S: 605 | GET <filename>.html
S -> C: 606 | Server Response // File is available
S -> C: 608 | Server Response // File is NOT available
If the requested is available at the server, the server’s response message to the client’s file request will
be constructed using the TLS record protocol. Its parameters are: Compression - None; Message MAC:
SHA-256; Encryption/Decryption: AES-192-CCM will be used.

### Running Code

To run code, install a python3 and then run the following command,
First install the dependency. 
```bash
  pip install -r requirements.txt
```
Now, run server,
```bash
  python3 ./server.py -n myname -m S -q serverport
```
for windows,

```bash
  python ./server.py -n myname -m S -q serverport
```
• m: mode (sender/ receiver)

• q: server port

• myname:  server name (should be of 6B)


Now, run client ,
```bash
  python3 ./client.py -n myname -m R -d serverIP -q serverport
```
for windows,

```bash
  python ./client.py -n myname -m R -d serverIP -q serverport
```
• myname: client name (should be of 6B)

• m: mode (sender/ receiver)

• d:  server address

• q:  server port

