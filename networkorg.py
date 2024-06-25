from Crypto.Cipher import AES
from json import dumps, loads
from os import urandom
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from _thread import start_new_thread

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

from Crypto.Hash import SHA256
from Crypto.Hash import HMAC, SHA3_512
from Crypto.Signature import pkcs1_15

import sys
import time



class Network:
    def __init__(self, cip, cport, ip, port):
        self.port = port
        self.ip = ip
        self.CA_ip = cip
        self.CA_port = int(cport)
        self.priv_key = RSA.generate(2048)
        self.pub_key = self.priv_key.public_key()

        self.BLOCK_SIZE = 32
        self.maxID = 0

        fo = open("CAPublicKey.txt", 'r')
        self.CA_pub_key = RSA.importKey(fo.read())
        fo.close()

        self.IPTable = {}
        self.get_certificate()

    def ping_starter(self):
        while True:
            try:
                start_new_thread(self.ping, ())
            except:
                pass
            time.sleep(4.7)

    def ping(self):
        iptable = self.IPTable
        offline = []
        if self.IPTable:
            try:
                for i in iptable.keys():
                    s = socket(AF_INET, SOCK_STREAM)
                    try:
                        ip, port = (self.IPTable[i]).split(":")
                        s.connect((ip, int(port)+1))
                        s.close()
                    except:
                        offline.append(i)
                for i in offline:
                    del iptable[i]
            except:
                pass

            try:
                self.IPTable = iptable
            except:
                pass
                                                                                        

    def get_certificate(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.CA_ip, self.CA_port))

        plaintext = dumps({'key': (self.pub_key.exportKey()).hex(), 'flag': "server"}).encode()

        key = urandom(16)
        aes_enc_obj = AES.new(key, AES.MODE_ECB)
        ciphertext = aes_enc_obj.encrypt(pad(plaintext, self.BLOCK_SIZE))
        rsa_enc_obj = PKCS1_OAEP.new(self.CA_pub_key)
        sock.send(dumps({'msg': (ciphertext).hex(), 'msgkey': (rsa_enc_obj.encrypt(key)).hex() }).encode())

        received = loads(sock.recv(8192).decode())
        
        ## Checking received certificate
        Certificate = bytes.fromhex(received['Certificate'])
        Signature = bytes.fromhex(received['Signature'])
        digest = SHA256.new(Certificate)
        try:
            pkcs1_15.new(self.CA_pub_key).verify(digest, Signature)
            msg = loads(Certificate)
            if(bytes.fromhex(msg['pub_key']) == self.pub_key.exportKey() and msg['ID'] == "Server"):
                print("Certificate received from CA.")
                self.certificate = received
                self.start()
            else:
                print("Invalid")
        except Exception as e:
            print(e)
            print("Invalid 2")


    def start(self):
        start_new_thread(self.ping_starter, ())
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.ip, 9200))
        sock.listen()
        print("Network started at:   "+self.ip+":"+str(self.port))
        while True:
            (client, _) = sock.accept()
            start_new_thread(self.handle_request, (client,))

    def handle_request(self, client):
        received = loads(client.recv(8192))
        try:
            if "register" in received.keys():
                client.send(dumps(self.certificate).encode())

                received = loads(client.recv(8192))

                ## Decrypting data received from client
                rsa_enc_obj = PKCS1_OAEP.new(self.priv_key)
                try:
                    msgkey = rsa_enc_obj.decrypt( bytes.fromhex(received['msgkey']) )
                except:
                    print("Key Error. ")

                msg = bytes.fromhex(received['msg'])
                aes_enc_obj = AES.new(msgkey, AES.MODE_ECB)
                try:
                    msg = unpad(aes_enc_obj.decrypt(msg), self.BLOCK_SIZE)
                except:
                    print("key error")

                #Shoudl work from here
                if self.IPTable:
                    #ID = max(self.IPTable.keys()) + 1
                    ID = self.maxID + 1
                    self.maxID = self.maxID + 1
                else:
                    ID = 1
                    self.maxID += 1
                    
                msg = loads(msg)
                port = msg['port']
                pub_key = bytes.fromhex(msg['pub_key'])
                ip = msg['ip']

                ## Preparing message for CA to request Certificate for client
                message = dumps({'pub_key': pub_key.hex(), 'ID': ID, 'ip': ip, 'port': port}).encode()
                digest = SHA256.new(message)
                signature = pkcs1_15.new(self.priv_key).sign(digest)

                sock1 = socket(AF_INET, SOCK_STREAM)
                sock1.connect((self.CA_ip, self.CA_port))
                sock1.send(dumps({'message': (message).hex(), 'signature': (signature).hex(), 'certificate': self.certificate}).encode())
                
                received = loads(sock1.recv(8192).decode())

                certificate = bytes.fromhex(received['Certificate'])
                signature = bytes.fromhex(received['Signature'])
                digest = SHA256.new(certificate)
                try:
                    pkcs1_15.new(self.CA_pub_key).verify(digest, signature)
                    msg = loads(certificate)
                    if(bytes.fromhex(msg['pub_key']) == pub_key and msg['ip'] == ip and msg['port'] == port and msg['ID'] == ID):
                        client.send(dumps(received).encode())
                        self.IPTable[ID] = ip+":"+str(port)
                except:
                    print("Error")
                            
                
            elif "requestIPTable" in received.keys():
                
                message = {'iptable': self.IPTable, 'TS': time.time()}
                message = dumps(message).encode()
                digest = SHA256.new(message)
                
                signature = pkcs1_15.new(self.priv_key).sign(digest)
                client.send(dumps({'message': (message).hex(), 'signature': (signature).hex()}).encode())
        except:
            pass


if __name__ == '__main__':
    cip, cport = (sys.argv[1]).split(":")
    
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    tip = s.getsockname()[0]
    server = Network(cip, cport, tip, port=9200)
