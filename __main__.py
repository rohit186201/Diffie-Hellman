"""
Author : abhishek18620
Date : 2018-03-30
File : __main__.py
Doc: http://asyncio.readthedocs.io/en/latest/webscraper.html
"""
from DiffieHellman.finitefield.finitefield import FiniteField
from DiffieHellman.elliptic import *
from Encryption import EncryptionECDH
import asyncio
import time
import pickle
import argparse

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
        return "({0})".format(self.list)

    def getIdentity(self):
        return self.identity

    def getMsg(self):
        return self.msg

class ClientInfo:
    def __init__(self, clientname):
        self.client = clientname
        self.auth = False

    def setSecretKey(self, secretkey):
        self.secretkey = secretkey

    def getKey(self):
        return self.secretkey

    def getClientName(self):
        return self.clientname

    def setAuthState(self, state):
        self.auth = state

    def getAuthState(self):
        return self.auth

class Server:
    ques={
        "what is your name": "Server",
        "what do you do": "I serves authnticated clients"
    }

    def __init__(self,host):
        print(self.ques)
        self.host=host
        self.client_dict = {}
        self.loop=asyncio.get_event_loop()
        self.coro=asyncio.start_server(self.handleClient,self.host,7777,loop=self.loop)
        server=self.loop.run_until_complete(self.coro)
        print("Serving on : {0}".format(server.sockets[0].getsockname()))
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            print("Server Stopped...............................\n\n\n")

    def AddQuestion(self ,que ,ans):
        self.ques[que]=ans

    async def handleClient(self, reader, writer):
        data = await reader.read(200)
        #data should be a pickleable object
        messagetemp = pickle.loads(data)
        print("@DEBUG --> {0}".format(messagetemp))
        clientname = messagetemp.identity
        if clientname in self.client_dict:
            print("Attempt to Man in the middle, Attempt to fake client {0}".format(clientname))
            return

        if clientname not in self.client_dict: # pre auth converstaion
            point = self.pickleableToPoint(messagetemp)
            print("Calculating shared secret for server side")
            self.encrypt = EncryptionECDH("Server", point)
            self.client_dict[clientname] = ClientInfo(clientname)
            secretKey = self.encrypt.extractSharedKey()
            self.client_dict[clientname].setSecretKey(secretKey)
            self.client_dict[clientname].setAuthState(True)
            print("{0} authenticated".format(clientname))

            # Sending server public key now to client
            # this conversation can't be encrypted as shared secret hasn't been established
            tempkey = self.encrypt.extractPublicKey()
            to_be_sent_temp = pickleable_Point(tempkey.x , tempkey.y, clientname)
            print("to be sent = {0}".format(to_be_sent_temp))
            to_be_sent = pickle.dumps(to_be_sent_temp)
            writer.write(to_be_sent)
            # await writer.drain()
            # print("Close the client socket")
        while True:
            data = await reader.read(200)
            print(data)
            messagetemp = pickle.loads(data)
            clientname = messagetemp.identity
            print("@DEBUG Received message from {0} msg = {1}".format(clientname, messagetemp.getMsg()))
            # Msg = pickleableToMsg(messagetemp)
            Msg = messagetemp
            secretKey = self.client_dict[clientname].getKey()
            message = self.encrypt.decryptMessage(Msg.getMsg(), secretKey)
            print(message)
            idx = int(message[len(message) - 1]) + 1
            #reply
            encrypted_msg = self.encrypt.encryptMessage("NEW_REPLY" + str(idx), secretKey)
            print("@DEBUG {0}".format(encrypted_msg))
            message = pickleable_Message("server", encrypted_msg)
            # message=pickleable_Message(encrypted_msg)
            msg = pickle.dumps(message)
            print("Pickled obj : {0}".format(repr(msg)))
            writer.write(msg)

    def read_msg_and_reply(self, data):
        messagetemp = pickle.loads(data)
        clientname = messagetemp.identity
        print("@DEBUG Received message from {0} msg = {1}".format(clientname, messagetemp.getMsg()))
        # Msg = pickleableToMsg(messagetemp)
        Msg = messagetemp
        secretKey = self.client_dict[clientname].getKey()
        message = self.encrypt.decryptMessage(Msg.getMsg(), secretKey)
        print(message)
        idx = ord(message[message.lenght() - 1])
        #reply
        encrypted_msg = self.encrypt.encryptMessage("NEW_REPLY" + str(idx), secretKey)
        print("@DEBUG {0}".format(encrypted_msg))
        message = pickleable_Message(self.identity, encrypted_msg)
        # message=pickleable_Message(encrypted_msg)
        msg = pickle.dumps(message)
        print("Pickled obj : {0}".format(repr(msg)))
        self.writer.write(msg)

    #converts pickleable to Point
    def pickleableToPoint(self, obj):
        F=FiniteField(3851,1)
        curve=EllipticCurve(a=F(324),b=F(1287))
        return Point(curve,F(obj.x),F(obj.y))

    def pickleableToMsg(self, obj):
        return pickleable_Message(obj.identity, obj.msg)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--host",type=str,help="server you want to host")
    args=parser.parse_args()
    if args.host:
        serverobj=Server(args.host)
