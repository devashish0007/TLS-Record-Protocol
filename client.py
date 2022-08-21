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
    key_file.write(privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))

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
        with open(name.decode()+"Certificate.txt", 'wb') as certificateFile:
            certificateFile.write(cerData+hashCerData)

    # print("Certificate Recived!...")

    return privateKey


def verifyCertificate(cipherText):

    code = cipherText[0:3]
    reciverName = cipherText[3:9]
    cerData = cipherText[9:]

    if code == b'602':
        # verify the certificate
        certificateData = cerData[0:834]
        signature = cerData[834:]

        with open("CAPublicKey.txt", "rb") as key_file:
            CAPublicKey = serialization.load_pem_public_key(key_file.read())
            try:
                CAPublicKey.verify(signature, certificateData, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                # key establishment start
                KP = os.urandom(48)
                serverPK = certificateData[14:814]
                serverPK = serialization.load_pem_public_key(serverPK)
                encKeyS = serverPK.encrypt(KP,
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None))

                cipherText = b'603' + encKeyS
                return KP, cipherText
                # key establishment end
            except:
                print("Signature Verification fails..")

                exit()


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
    parser.add_argument('-d', type=str)
    parser.add_argument('-q', type=int)
    # CA IP & Port
    parser.add_argument('-a', type=str, default="127.0.0.1")
    parser.add_argument('-p', type=int, default=12345)

    args = parser.parse_args()

    name = args.n
    mode = args.m
    if (mode.lower() != 'r'):
        print("Please run client in receiver mode(R)...")
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
            clientCertificate = serialization.load_pem_public_key(key_file.read()[14:814])
            privateKey = loadPrivateKey(name)

    except:
        privateKey = generateCertificate(args.n, args.a, args.p)

    # Create a socket
    clientSocket = socket.socket()
    # print("Sleeps for 1 seconds..")
    time.sleep(1)
    clientSocket.connect((args.d, args.q))
    # print("Connect to Sender..")
    with open(f"{name}Certificate.txt", 'rb') as certificateFile:
        certificate = certificateFile.read()

    message = b'601' + bytes(name, 'ascii') + certificate
    clientSocket.send(message)

    # Verify servers certificate
    message = clientSocket.recv(1500)

    clientCode = message[0:3]
    clientName = message[3:9].decode()


    KP, verify = verifyCertificate(message)
    if verify:
        clientSocket.send(verify)

########################### key establishment start ##############################################
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=48, otherinfo=None)
    masterKey = ckdf.derive(KP)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"clientWriteMAC")
    clientWriteMAC = ckdf.derive(masterKey)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=24, otherinfo=b"serverWrite")
    clientWrite = ckdf.derive(masterKey)
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=16, otherinfo=b"initialVector")
    iv = ckdf.derive(masterKey)

########################### key establishment complete ##############################################
    # creating cipher
    cipher = Cipher(algorithms.AES(clientWrite), modes.CBC(iv))



    while True:
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        print("----------to quit enter \'exit\'----------")
        request = input("Enter the file name : ")
        if request.lower() == 'exit':
            clientSocket.close()
            exit()
        message = b'605'+b'GET' + bytes(f"{request}.html", 'ascii')
        # fragment, encrypt & hash data request
        padder = blockPadding.PKCS7(128).padder()
        message = padder.update(message)
        message += padder.finalize()


        contentType = 65  # dummy
        contentType = contentType.to_bytes(1, 'little')
        majorVersion = 3
        majorVersion = majorVersion.to_bytes(1, 'little')
        minorVersion = 3
        minorVersion = minorVersion.to_bytes(1, 'little')
        compressedLength = len(message)
        compressedLength = compressedLength.to_bytes(2, 'little')

        # creating new hmac object using sha256 hash algorithm
        digest_maker = hmac.new(clientWriteMAC, message, hashlib.sha256)


        # generate digest of 32 bytes
        digest = digest_maker.digest()

        message = message + digest

        cipherText = encryptor.update(message) + encryptor.finalize()


        header = contentType + majorVersion + minorVersion + compressedLength

        message = header + cipherText

        clientSocket.send(message)
        message = clientSocket.recv(2048)

        print(message[3:])



