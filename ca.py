import argparse
import socket
import string
import random
from datetime import date
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


def generateKeyPair():
    # Generate CA Private Key
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Generate CA Public Key
    publicKey = privateKey.public_key()
    with open("CAPublicKey.txt", 'wb') as outfile:
        # Store CA Public Key
        outfile.write(publicKey.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return privateKey


def generateCertificate(CAprivateKey, clientPK, clientName):
    clientName = CAprivateKey.decrypt(clientName, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    d1 = date.today()
    startDate = bytes(str(d1), 'ascii')
    d2 = date(d1.year + 1, d1.month, d1.day)
    endDate = bytes(str(d2), 'ascii')
    nonce = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=8))
    nonce = bytes(nonce, 'ascii')
    certData = clientName + nonce + clientPK + startDate + endDate


    hashCertData = CAprivateKey.sign(certData, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    clientPK = serialization.load_pem_public_key(clientPK)
    encHashCertData = clientPK.encrypt(hashCertData, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    certificateInfo = certData + encHashCertData

    certificate = b'302' + clientName + certificateInfo

    return certificate, clientName


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=int)
    parser.add_argument('-o', type=str)

    args = parser.parse_args()
    # Generate Pu, Pr
    privateKey = generateKeyPair()

    # Create a socket
    CASocket = socket.socket()
    # reserving port
    port = args.p
    file = open(args.o, 'w')

    # Bind socket to port
    CASocket.bind(('', port))
    # socket listening
    CASocket.listen(5)

    print("starts TCP server to listen on port: ", args.p)
    file.write(f"starts TCP server to listen on port: {args.p}\n")
    file.close

    # a forever loop until we interrupt it or an error occurs
    while True:
        print("Wait for messages from clients..")
        file = open(args.o, 'a')
        file.write(f"Wait for messages from clients..\n")
        file.close()
        print("Type Ctrl - C to finally quit")
        # Establish connection with client.
        clientSocket, clientAddr = CASocket.accept()
        file = open(args.o, 'a')
        print(f"Connection established with clients..")
        file.write(f"Connection established with clients..\n")
        file.close()
        # send a thank you message to the client. encoding to send byte type.


        request = clientSocket.recv(1500)
        file = open(args.o, 'a')
        print(f"received certificate request from clients..")
        file.write(f"received certificate request from client {request[3:803].decode()}..\n")
        file.close()
        if request[0:3] == b'301':
            certificate, clientName = generateCertificate(privateKey, request[3:803], request[803:])
            clientSocket.send(certificate)
            file = open(args.o, 'a')
            print(f"Sent certificate to client {clientName} ..\n")
            file.write(f"Sent certificate to clients {clientName}..\n")
            file.close()
        else:
            print(f"Incorrect Request from client {request[3:803].decode()}!")
            file = open(args.o, 'a')
            file.write(f"Incorrect Request from clients {request[3:803].decode()}!")
            file.close


        # Close the connection with the client
        clientSocket.close()
