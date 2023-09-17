"""
Author : abhishek18620
Date : 2018-04-01
File : Encryption.py
"""
from DiffieHellman import diffie_hellman
import cryptography

class Message:
    def __init__(self, identity, msg):
        self.identity = identity
        self.msg = msg

    def getIdentity(self):
        return self.identity

    def setIdentity(self, identity):
        self.identity = identity

    def getMsg(self):
        return self.msg

    def setMsg(self, Msg):
        self.msg = Msg


class EncryptionECDH(diffie_hellman.ECDH):
    def __init__(self, person, receivedKey):
        #generates all
        self.generate(person)
        self.secretKey = self.generateSharedSecret(person, receivedKey)
        #print("Here {0}".format(self.secretKey))

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
