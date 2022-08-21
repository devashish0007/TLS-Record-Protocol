import argparse
import os
import socket
import time


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import hmac
import hashlib
from cryptography.hazmat.primitives import padding as blockPadding



def generateKeyPair(name):
    # Generate CA Private Key
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    # Generate CA Public Key
    publicKey = privateKey.public_key()

    publicKey = publicKey.public_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PublicFormat.SubjectPublicKeyInfo)

    key_file = open(f"{name}PrivateKey.pem", 'wb')
    # Store CA Public Key
    key_file.write(privateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    key_file.close()
    return privateKey, publicKey


def loadPrivateKey(name):
    keyFile = open(f"{name}PrivateKey.txt", "rb")
    privateKey = serialization.load_pem_private_key(
        keyFile.read(),
        password=None,
    )
    return privateKey


def generateCertificate(name, caIP, caPort):
    # Generate Pu, Pr
    privateKey, publicKey = generateKeyPair(name)
    # Create a socket object
    clientSocket = socket.socket()
    # connect to the server
    clientSocket.connect((caIP, caPort))
    # Sleep for 1 seconds
    # print("Sleeps for 1 seconds ..")
    time.sleep(1)

    with open("CAPublicKey.txt", "rb") as key_file:
        CAPublicKey = serialization.load_pem_public_key(key_file.read())

    name = bytes(name, 'ascii')
    encName = CAPublicKey.encrypt(name,
                                  padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                               label=None))

    # message = b'301' + puKey.read() + encName
    message = b'301' + publicKey + encName
    # send data to CA server to get the certificate.
    clientSocket.send(message)
    # print("Contact CA and requests Certificate ..")

    certificate = clientSocket.recv(1500)
    # print("receive certificate from CA..")
    code = certificate[0:3]
    name = certificate[3:9]
    certificateInfo = certificate[9:]

    if code == b'302':
        cerData = certificateInfo[0:834]
        encHashCerData = (certificateInfo[834:])
        hashCerData = privateKey.decrypt(encHashCerData, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                      algorithm=hashes.SHA256(), label=None))
        with open(name.decode() + "Certificate.txt", 'wb') as certificateFile:
            certificateFile.write(cerData + hashCerData)

    # print("Certificate Recived!...")

    return privateKey


def verifyCertificate(cipherText):
    code = cipherText[0:3]
    reciverName = cipherText[3:9]
    cerData = cipherText[9:]

    if code == b'601':
        # verify the certificate
        certificateData = cerData[0:834]
        signature = cerData[834:]

        with open("CAPublicKey.txt", "rb") as key_file:
            CAPublicKey = serialization.load_pem_public_key(key_file.read())
            try:
                CAPublicKey.verify(signature, certificateData,
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                   hashes.SHA256())

                # key establishment start
                print(f"{name} verifies {reciverName.decode()}'s certificate..")
                keyS = os.urandom(24)
                nonce = os.urandom(16)
                senderPK = certificateData[14:814]
                senderPK = serialization.load_pem_public_key(senderPK)
                encKeyS = senderPK.encrypt((keyS) + (nonce),
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None))
                # len(encKeyS) = 512
                # print("Length of : ", len(encKeyS))
                cipherText = b'503' + encKeyS + bytes(inputFile, 'ascii')
                # send request to sender
                print("Generate session key..")
                print("send encrypted session key..")
                # receiverSocket.send(cipherText)
                # key establishment end
            except:
                print("Signature Verification fails..")
                exit()

            print("sucessfull!.......")


def fragmentation(message):
    fragment = []
    size = 2048
    length = len(message)
    for start in range(0, length, 2048):
        fragment.append(message[start: start + size])

    return fragment





if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=str)
    parser.add_argument('-m', type=str)
    parser.add_argument('-q', type=int)
    # CA configuration
    parser.add_argument('-a', type=str, default="127.0.0.1")
    parser.add_argument('-p', type=int, default=12345)

    args = parser.parse_args()

    name = args.n
    mode = args.m
    if (mode.lower() != 's'):
        print("Please run server in sender mode(S)...")
        exit()
    # reserving port
    port = args.q

    try:
        with open("CAPublicKey.txt", "rb") as key_file:
            CAPublicKey = serialization.load_pem_public_key(key_file.read())

    except:
        print("CA's public key not availble...")
        exit()

    # check for certificate availability
    try:
        with open(f"{name}Certificate.txt", "rb") as key_file:
            serverCertificate = serialization.load_pem_public_key(key_file.read()[14:814])
            privateKey = loadPrivateKey(name)

    except:
        privateKey = generateCertificate(args.n, args.a, args.p)

    # Create a socket
    CASocket = socket.socket()

    # Bind socket to port
    CASocket.bind(('', port))
    # socket can listen up to 10 request
    CASocket.listen(20)

    # Establish connection with client.
    clientSocket, clientAddress = CASocket.accept()

    message = clientSocket.recv(1500)

    clientCode = message[0:3]
    clientName = message[3:9].decode()

    if clientCode == b'601':
        clientCertificate = message[9:]

        if not (verifyCertificate(clientCertificate)):
            # print("Successfull!.........")

            with open(f"{name}Certificate.txt", 'rb') as certificateFile:
                certificate = certificateFile.read()
                message = b'602' + bytes(name, 'ascii') + certificate
                clientSocket.send(message)


        else:
            print("verificiation fails...")
            exit()
    else:
        print(f"Incorrect Request from client {clientName}!")

########################### key establishment start ##############################################
    message = clientSocket.recv(1500)
    clientCode = message[0:3]



    if clientCode == b'603':
        encKP = message[3:]
        KP = privateKey.decrypt(encKP,
                                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(),
                                                    label=None))


        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=48, otherinfo=None)
        masterKey = ckdf.derive(KP)
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"clientWriteMAC")
        serverWriteMAC = ckdf.derive(masterKey)
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=24, otherinfo=b"serverWrite")
        serverWrite = ckdf.derive(masterKey)
        ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=b"initialVector")
        iv = ckdf.derive(masterKey)

########################### key establishment complete ##############################################
    cipher = Cipher(algorithms.AES(serverWrite), modes.CBC(iv))

    while True:
        try:
            encryptor = cipher.encryptor()
            decryptor = cipher.decryptor()
            message = clientSocket.recv(2500)

            contentType = message[0]  # dummy
            majorVersion = message[1]
            minorVersion = message[2]
            compressedLength = message[3:5]
            compressedLength = int.from_bytes(compressedLength, "little")

            message = message[5:]

            message = decryptor.update(message) + decryptor.finalize()

            clientDigest = message[compressedLength:]
            message = message[0:compressedLength]

            digest_maker = hmac.new(serverWriteMAC, message, hashlib.sha256)
            serverDigest = digest_maker.digest()

            if not (hmac.compare_digest(serverDigest, clientDigest)):
                print("Message intigrity lost...")
                continue
            else:

                unpadder = blockPadding.PKCS7(128).unpadder()
                if len(message) > 16:
                    message = unpadder.update(message)
                else:
                    message = message.split(b'.html')[0]+b'.html'



            if message[0:3] == b'605':
                fileName = (message[6:]).decode()

                try:
                    file = open(fileName, 'rb')
                    fileContet = file.read()
                    file.close()
                    message = b'606' + fileContet

                except:

                    message = b'608'+b'Error:file Not Available'


            clientSocket.send(message)
        except:
            exit()
