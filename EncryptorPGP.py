import lzma
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


class EncryptionPGP:
    'Base Methods for all the Encryption'
    encryptionObj = 0
    Name = 'Faizan'
    fileName = 'Message.txt'
    cwd = os.getcwd()

    def __init__(self):
        EncryptionPGP.encryptionObj += 1

    def loaddata(self, fileName):
        self.fileName = fileName
        with open(self.fileName, "rb") as M:
            message = M.read()
        return message

    def encrypt(self, message, myPrivate_key, recvPublic_key):
        self.message = message
        self.myprivate_key = myPrivate_key
        self.recvPublic_key = recvPublic_key

    def KeyGen(self):
        print("key Generation Start...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        print("Private key Generated!")
        public_key = private_key.public_key()
        print("Public Key Generated!")
        keySet = {"private_key": private_key, "public_key": public_key}
        return keySet

    def SaveKeys(self, keySet):
        pem_private = keySet['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
   
        with open(self.cwd+'\\'+self.Name+'private_key.pem', 'wb') as f:
            f.write(pem_private)

        pem_public = keySet['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.cwd+'\\'+self.Name+'public_key.pem', 'wb') as f:
            f.write(pem_public)

    def loadKey(self, key):
        with open(key, "rb") as key_file:
            any_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return any_key

    def digitalSignature(self, message, private_key):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def Envelope(self, message, signature):
        data = (signature + b"||Append||" + message)
        compressedData = lzma.compress(data)
        return compressedData

    def genSymitricKey(self):
        return Fernet.generate_key()

    def symitricalEncryption(self, key, envelope):
        f = Fernet(key)
        symytricalEncryption = f.encrypt(envelope)
        return symytricalEncryption

    def symkeyEncryption(self, key, encrkey):
        keyEncrypted = Usmanpublic_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return keyEncrypted

    def output(self, message, key):
        directory = self.cwd + '\\send'
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(self.cwd+'\\'+'Send'+'\\'+'encrypMessage.csv', 'wb') as f:
            f.write(message)

        with open(self.cwd+'\\'+'Send'+'\\'+'encrypKey.pem', 'wb') as f:
            f.write(key)


# This would create first object of EncryptionPGP class
encrypt = EncryptionPGP()
encrypt_MsgPath = input("Enter Path of Your Message.csv:\n")
# encrypt_MsgPath = 'E:\\Assignment\\Messagetest.csv'
message = encrypt.loaddata(encrypt_MsgPath)

# IF we need to create keys
keySet = encrypt.KeyGen()  # dectionary for public and private key
encrypt.SaveKeys(keySet)

# Otherwise load keys
encrypt_keyPath = input("Enter Path of Your Friends Public Key Pem file:\n")
# encrypt_keyPath = 'E:\\Assignment\\Usmanpublic_key.pem'
Usmanpublic_key = encrypt.loadKey(encrypt_keyPath)

# Step 1 Adding digital signature
signature = encrypt.digitalSignature(message, keySet['private_key'])

# Step 2
compressedEnvelope = encrypt.Envelope(message, signature)

# Step 3
key = encrypt.genSymitricKey()
symEncryptedmsg = encrypt.symitricalEncryption(key, compressedEnvelope)

# Step 4
encryptedsymKey = encrypt.symkeyEncryption(key, Usmanpublic_key)

# Step 5
encrypt.output(symEncryptedmsg, encryptedsymKey)
