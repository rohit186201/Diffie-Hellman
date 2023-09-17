"""
Author : abhishek18620
Date : 2018-04-02
File : client_encryption.py
"""
#from DiffieHellman.elliptic import *
#from DiffieHellman.finitefield.finitefield import FiniteField
from DiffieHellman import diffie_hellman
import cryptography

class EncryptionECDH(diffie_hellman.ECDH):

    def __init__(self,person):
        #generates all
        self.generate(person)


    def secretGeneration(self,person,receivedKey):
        return self.generateSharedSecret(person,receivedKey)


    def extractPublicKey(self):
        return self.getPublic()

    def extractSharedKey(self):
        return self.getSharedSecret()

    def extractSecretKey(self):
        return self.getSecret()

    def encryptMessage(self, msg, secret_key):
        product = secret_key.x * secret_key.y
        encrypted_msg = []
        for ch in msg:
            encrypted_msg.append((ord(ch) * product).n)
        return encrypted_msg

    def decryptMessage(self, msg, secret_key):
        product = secret_key.x * secret_key.y
        decrypted_msg = ""
        for item in msg:
            ch = chr(item / product)
            decrypted_msg += str(ch)
        return decrypted_msg
