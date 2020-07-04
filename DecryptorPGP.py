import lzma
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


class DecryptionPGP:
    'Base Methods for all the decrypion'
    decrypionObj = 0
    cwd = os.getcwd()
    username = 'Faizan'
    encrypt_MsgPath = 'path'
    encrypt_KeyPath = 'path'
    private_KeyPath = 'path'
    public_KeyPath = 'path'
    # os.makedirs(os.path.dirname(filename), exist_ok=True)

    def __init__(self, username, encrypt_MsgPath,
                 encrypt_KeyPath, private_KeyPath, public_KeyPath):
        DecryptionPGP.decrypionObj += 1
        DecryptionPGP.username = username
        DecryptionPGP.encrypt_MsgPath = encrypt_MsgPath
        DecryptionPGP.encrypt_KeyPath = encrypt_KeyPath
        DecryptionPGP.private_KeyPath = private_KeyPath
        DecryptionPGP.public_KeyPath = public_KeyPath

    def loaddata(self, encrypt_MsgPath):
        if os.path.exists(encrypt_MsgPath):
            with open(self.encrypt_MsgPath, "rb") as M:
                message = M.read()
        else:
            print("Path Invalid")
            return
        return message

    def decryp(self, message, myPrivate_key, recvPublic_key):
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
        # print("Private key Generated!")
        public_key = private_key.public_key()
        # print("Public Key Generated!")
        keySet = {"private_key": private_key, "public_key": public_key}
        return keySet

    def messageSave(self, message):
        print("Massage Saved at: " + self.cwd + "\\MessageDecrypted.csv")
        with open(self.cwd+'\\MessageDecrypted.csv', 'wb') as f:
            f.write(message)

    def loadKeyPrivate(self, key):
        if os.path.exists(key):
            with open(key, "rb") as key_file:
                any_key = serialization.load_pem_private_key(
                    key_file.read(),
                    backend=default_backend(),
                    password=None
                )
        else:
            print("Private Key Path Invalid")
            return
        return any_key

    def loadKeyPublic(self, key):
        if os.path.exists(key):
            with open(key, "rb") as key_file:
                any_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
        else:
            print("Public Key Path Invalid")
            return

        return any_key

    def signatureVarify(self, signature, public_key, message):
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def deEnvelope(self, message):
        data = lzma.decompress(message)
        index = data.find(b'||Append||')
        signature = data[:index]
        data = data[index:]
        msgReceived = data.replace(b'||Append||', b'')
        deEnvelope = {'signature': signature, 'message': msgReceived}
        return deEnvelope

    def genSymitricKey(self):
        return Fernet.generate_key()

    def symitricalDecryption(self, key, envelope):
        f = Fernet(key)
        symytricalDecryption = f.decrypt(envelope)
        return symytricalDecryption

    def symkeyDecrypion(self, key, private_key):
        decryptedKey = private_key.decrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decryptedKey

    def inputMessage(self, message):
        if os.path.exists(message):
            with open(message, 'rb') as f:
                encrypMessage = f.read()
        else:
            print("Path Invalid")
            return
        return encrypMessage

    def inputKey(self, key):
        if os.path.exists(key):
            with open(key, 'rb') as f:
                encryptKey = f.read()
        else:
            print("Path Invalid")
            return
        return encryptKey


def main():
    print("Welcome to DecryptionPGP\n")
    # This would create first object of EncryptionPGP class
    username = input("Enter username:\n")
    # message = decryp.loaddata('Message.csv')

    # IF we need to create keys
    # keySet = decryp.KeyGen() #dectionary for public and private key
    # decryp.SaveKeys(keySet)

    # Otherwise load keys
    encrypt_MsgPath = input("Enter Path of Encrypted Message:\n")
    encrypt_KeyPath = input("Enter Path of Encrypted Key:\n")
    private_KeyPath = input("Enter Your Private Key Path to unlock the key:\n")
    public_KeyPath = input("Enter Sender's Public key Path to varify DS:\n")

    decryp = DecryptionPGP(
                username,
                encrypt_MsgPath,
                encrypt_KeyPath,
                private_KeyPath,
                public_KeyPath
                )
    # Step 5
    # encrypt_MsgPath = 'E:\Assignment\Send\encrypMessage.csv'
    encrypMsg = decryp.inputMessage(encrypt_MsgPath)
    print("Message Accessed Successfully\n")

    # encrypt_KeyPath = 'E:\Assignment\Send\encrypKey.pem'
    encrypKey = decryp.inputKey(encrypt_KeyPath)
    print("Key Accessed Successfully\n")

    # private_KeyPath = 'E:\Assignment\Usmanprivate_key.pem'
    Usmanprivate_key = decryp.loadKeyPrivate(private_KeyPath)
    print("Private Key Loaded\n")

    # public_KeyPath = 'E:\Assignment\Faizanpublic_key.pem'
    faizanpublic_key = decryp.loadKeyPublic(public_KeyPath)
    print("Public Key Loaded\n")

    # Step 4
    decrypedsymKey = decryp.symkeyDecrypion(encrypKey, Usmanprivate_key)
    print("Key Decrypted Successfully\n")
    # Step 3
    # key = decryp.genSymitricKey()
    symDecrypedMsg = decryp.symitricalDecryption(decrypedsymKey, encrypMsg)
    print("Message Decrypted Successfully\n")
    # Step 2
    # deEnvelope = {'Message': message, 'DigitalSignature':signature}
    deEnvelope = decryp.deEnvelope(symDecrypedMsg)
    print("Message DeEnveloped Successfully\n")
    # Step 1
    decryp.signatureVarify(
            deEnvelope['signature'],
            faizanpublic_key,
            deEnvelope['message']
    )
    print("Message Signature Varified\n")
    decryp.messageSave(deEnvelope['message'])
    print("Decrypted Message Saved At Current Path\n")


if __name__ == "__main__":
    main()
