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

class pickleable_Point:

    def __init__(self,x,y,identity):
        self.x=int(x)
        self.y=int(y)
        self.identity=identity

    def __str__(self):
        return "({0}, {1})".format(self.x, self.y)

class pickleable_Message:

    def __init__(self, identity, msg):
        self.identity = identity
        self.msg = msg

    def __str__(self):
        return "({0} {1})".format(self.identity, self.msg)

    def getIdentity(self):
        return self.identity

    def getMsg(self):
        return self.msg


class Client:

    def __init__(self,identity,host):
        self.host=host
        self.identity=identity
        self.loop=asyncio.get_event_loop()
        messagetemp=self.initial_message_build()
        self.auth = False
        client=self.loop.run_until_complete(self.open_connection(self.loop))
        self.loop.run_until_complete(self.tcp_sender_auth(messagetemp))
        if self.auth:
            self.loop.run_until_complete(self.tcp_sender_post_auth("NEW MSG",self.loop))

        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print("Server Stopped...............................\n\n\n")
        self.loop.close()

    def __del__(self):
        # self.reader.close()
        self.writer.close()


    def initial_message_build(self):
        """
        generates
        1) secret key
        2) public key
        """
        self.encrypt=EncryptionECDH(self.identity)
        return self.encrypt.extractPublicKey()

    async def open_connection(self, loop):
        self.reader,self.writer = await asyncio.open_connection(self.host,7777,loop=loop)


    async def tcp_sender_auth(self,messagetemp):
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
        message=pickleable_Point(messagetemp.x,messagetemp.y,self.identity)
        print(message)
        msg=pickle.dumps(message)
        print("Pickled obj : {0}".format(repr(msg)))
        self.writer.write(msg)
        """
        Initially this should be the server's
        public Key which is received key in our case
        """
        data_received=await self.reader.read(200)
        data=pickle.loads(data_received)
        #call to create client side sharedsecret
        remote_pub_key = self.pickleableToPoint(pickle.loads(data_received))
        self.secretkey = self.encrypt.secretGeneration(self.identity, remote_pub_key)
        print("Remote pub key = {0}".format(remote_pub_key))
        await asyncio.sleep(0.5)
        self.auth = True
        # self.writer.close()

    async def tcp_sender_post_auth(self,messagetemp,loop):
        #while True:
        # Warning : client is waiting indefinitely
        # reader,writer= await asyncio.open_connection(self.host,7777,loop=loop)
        msg = "NEW_MSG1"
        while True:
            print("Sending message......{0}".format(msg))
            encrypted_msg = self.encrypt.encryptMessage(msg, self.secretkey)
            print("@DEBUG {0}".format(encrypted_msg))
            message = pickleable_Message(self.identity, encrypted_msg)
            msg_dump = pickle.dumps(message)
            print("Pickled obj : {0}".format(repr(msg_dump)))
            await asyncio.sleep(1)
            self.writer.write(msg_dump)

            #wait for reply
            data = await self.reader.read(200)
            print("data on client side {0}".format(data))
            reply = pickle.loads(data)
            clientname = reply.identity
            print("@DEBUG Received message from {0} msg = {1}".format(clientname, reply.getMsg()))
            # Msg = pickleableToMsg(messagetemp)
            Msg = reply
            secretKey = self.secretkey
            message = self.encrypt.decryptMessage(Msg.getMsg(), secretKey)
            print(message)
            idx = int(message[len(message) - 1]) + 1
            # idx = send_and_read_reply(msg)
            msg = "NEW_MSG" + str(idx)
            print(msg)

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
        encrypted_msg = self.encrypt.encryptMessage(messagetemp, self.secretkey)
        print("@DEBUG {0}".format(encrypted_msg))
        message = pickleable_Message(self.identity, encrypted_msg)
        # message=pickleable_Message(encrypted_msg)
        msg = pickle.dumps(message)
        print("Pickled obj : {0}".format(repr(msg)))
        self.writer.write(msg)
        """
        Initially this should be the server's
        public Key which is received key in our case
        """
        messagetemp = pickle.loads(data)
        clientname = messagetemp.identity
        print("@DEBUG Received message from {0} msg = {1}".format(clientname, messagetemp.getMsg()))
        # Msg = pickleableToMsg(messagetemp)
        Msg = messagetemp
        secretKey = self.client_dict[clientname].getKey()
        message = self.encrypt.decryptMessage(Msg.getMsg(), secretKey)
        print(message)

        data_received=await self.reader.read(200)
        data=pickle.loads(data_received)
        print(data)
        #call to create client side sharedsecret
        data=self.pickleableToMsg(pickle.loads(data_received))
        await asyncio.sleep(0.5)
        # writer.close()


    def pickleableToPoint(self,obj):
        F=FiniteField(3851,1)
        curve=EllipticCurve(a=F(324),b=F(1287))
        return Point(curve,F(obj.x),F(obj.y))

    def pickleableToMsg(self, obj):
        return Message(obj.identity, obj.msg)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--identity",type=str,help="--identity for specifying client's identity")
    parser.add_argument("--host",type=str,help="server you want to connect")
    args=parser.parse_args()
    if args.identity:
        clientobj=Client(args.identity,args.host)
