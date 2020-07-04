#Its a PGP Encryption Algorithm Implimentation to encrypt any big data file.


#To Encrypt
Install Following
python -m pip install cryptography
pip install lzma

run EncryptionPGP.py file

Enter the prompted information as shown in below example

You public and private key will be generated everytime you encrypt so this will be fixed in the next version

#Example
Enter Path of Your Message.csv:
E:\\Assignment\\Messagetest.csv  
key Generation Start...
Private key Generated!
Enter Path of Your Friends Public Key Pem file:
E:\\Assignment\\Usmanpublic_key.pem


#To Decrypt
Install Following
python -m pip install cryptography
pip install lzma

run DecryptionPGP.py file

enter the prompted details as follow according to your directory

file will be decrypted at your current working direcory


#Example
Welcome to DecryptionPGP

Enter username:
Faizan
Enter Path of Encrypted Message:
E:\Assignment\Send\encrypMessage.csv
Enter Path of Encrypted Key:
E:\Assignment\Send\encrypKey.pem  
Enter Your Private Key Path to unlock the key:
E:\Assignment\Usmanprivate_key.pem
Enter Sender's Public key Path to varify DS:
E:\Assignment\Faizanpublic_key.pem
Message Accessed Successfully

Key Accessed Successfully

Private Key Loaded

Public Key Loaded

Key Decrypted Successfully

Message Decrypted Successfully

Message DeEnveloped Successfully


Key Accessed Successfully

Private Key Loaded

Public Key Loaded

Key Decrypted Successfully

Message Decrypted Successfully

Message DeEnveloped Successfully

Message Signature Varified

Massage Saved at: e:\Assignment\MessageDecrypted.csv
Decrypted Message Saved At Current Path