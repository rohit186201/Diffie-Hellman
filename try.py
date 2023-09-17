"""
Author : abhishek18620
Date : 2018-03-30
File : client.py
"""
from DiffieHellman.finitefield.finitefield import FiniteField
from DiffieHellman.elliptic import *
from client_encryption import EncryptionECDH
import asyncio
import time
import argparse
import pickle

class pickleable:

    def __init__(self,x,y):
        self.x=int(x)
        self.y=int(y)

    def __str__(self):
        return "({0}, {1})".format(self.x, self.y)



class Client:

    def __init__(self,identity):
        self.identity=identity
        self.loop=asyncio.get_event_loop()
        messagetemp=self.initial_message_build()
        client=self.loop.run_until_complete(self.tcp_sender(messagetemp,self.loop))
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print("Server Stopped...............................\n\n\n")
        self.loop.close()

    def initial_message_build(self):
        """
        generates
        1) secret key
        2) public key
        """
        self.encrypt=EncryptionECDH(self.identity)
        return self.encrypt.extractPublicKey()

    async def tcp_sender(self,messagetemp,loop):
        #while True:
        reader,writer= await asyncio.open_connection('127.0.0.1',7777,loop=loop)
        print("Sending message......{0}".format(messagetemp))
        """
        converting object into bytes
        nonlocal msg1
        msg1=self.encrypt.extractPublicKey()
        WARNING : local object not pickleable , needs to be fixed
        nonlocal can be used but only in nested functions
        global can't be updated in local scope
        Workaround : create d a class pickleable with integer values
        """
        message=pickleable(messagetemp.x,messagetemp.y)
        print(message)
        msg=pickle.dumps(message)
        print("Pickled obj : {0}".format(repr(msg)))
        writer.write(msg)
        """
        Initially this should be the server's
        public Key which is received key in our case
        """
        data_received=await reader.read(100)
        data=pickle.loads(data_received)
        #call to create client side sharedsecret
        data=self.pickleableToPoint(pickle.loads(data_received))
        self.encrypt.secretGeneration(self.identity,data)
        await asyncio.sleep(0.5)
        writer.close()

    def pickleableToPoint(self,obj):
        F=FiniteField(3851,1)
        curve=EllipticCurve(a=F(324),b=F(1287))
        return Point(curve,F(obj.x),F(obj.y))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--identity",type=str,help="--identity for specifying client's identity")
    args=parser.parse_args()
    if args.identity:
        clientobj=Client(args.identity)
