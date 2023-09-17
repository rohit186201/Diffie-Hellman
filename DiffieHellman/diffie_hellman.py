"""
Author : abhishek18620
Date : 2018-03-31
File : diffie-hellman.py

"""

from .elliptic import *
from .finitefield.finitefield import FiniteField

import os

class ECDH:
    def generateSecretKey(self,numBits):
        return int.from_bytes(os.urandom(numBits // 8), byteorder='big')


    def sendDH(self, privateKey, generator):
        return privateKey * generator
        # return sendFunction(privateKey * generator)


    def receiveDH(self,privateKey, receiveFunction):
        return privateKey * receiveFunction()


    def slowOrder(self,point):
        Q = point
        i = 1
        while True:
            if type(Q) is Ideal:
                return i
            else:
                Q = Q + point
                i += 1

    def getSharedSecret(self):
        return self.sharedSecret

    def getSecret(self):
        return self.SecretKey

    def getPublic(self):
        return self.PublicKey

    def generate(self, person): #person just for debugging purposes
        F = FiniteField(3851, 1)
        """
        NOTE: a,b,x,y could be random as well
             Will see it later!!
        """
        # Curve: y^2 = x^3 + 324x + 1287
        curve = EllipticCurve(a=F(324), b=F(1287))

        basePoint = Point(curve, F(920), F(303))

        self.SecretKey = self.generateSecretKey(8)
        #bobSecretKey = generateSecretKey(8)
        #print("{0}Secret key is : {1}".format(person, repr(self.SecretKey)))
        #print('Secret keys are %d, %d' % (self.SecretKey, bobSecretKey))

        self.PublicKey = self.sendDH(self.SecretKey, basePoint)
        #print("{0}Public key is : {1}".format(person, self.PublicKey))
        #bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x:x)


    #receivedKey=
    def generateSharedSecret(self,person,receivedKey):
        self.sharedSecret = self.receiveDH(self.SecretKey, lambda: receivedKey)
        #sharedSecret2 = receiveDH(SecretKey, lambda: bobPublicKey)
        #print("{0} Shared secret is : {1}".format(person, repr(self.sharedSecret)))
        return self.sharedSecret
        #print('Shared secret is %s == %s' % (sharedSecret1, sharedSecret2))
        #print('extracing x-coordinate to get an integer shared secret: %d' % (sharedSecret1.x.n))

