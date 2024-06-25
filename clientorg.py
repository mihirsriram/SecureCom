from Crypto.Cipher import AES
from json import dumps, loads
from os import urandom
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from _thread import start_new_thread

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


from Crypto.Hash import SHA256, SHA512
from Crypto.Hash import HMAC, SHA3_512
from Crypto.Signature import pkcs1_15

import time
import sys


class Client:
    def __init__(self, sip, sport, ip, port):
        self.port = port
        self.ip = ip
        self.network_ip = sip
        self.network_port = int(sport)
        self.priv_key = RSA.generate(2048)
        self.pub_key = self.priv_key.public_key()

        self.BLOCK_SIZE = 32

        fo = open("CAPublicKey.txt", 'r')
        self.CA_pub_key = RSA.importKey(fo.read())
        fo.close()
        self.server_ts = 0
        self.IPTable = {}


        start_new_thread(self.ping_listener, ())
        self.register()
        
    def register(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.network_ip, self.network_port))

        sock.send(dumps({'register': "Register"}).encode())

        received = loads(sock.recv(8192).decode())

        ##Checking certificate from Server
        Certificate = bytes.fromhex(received['Certificate'])
        Signature = bytes.fromhex(received['Signature'])

        digest = SHA256.new(Certificate)
        try:
            pkcs1_15.new(self.CA_pub_key).verify(digest, Signature)
            msg = loads(Certificate)
            if(msg['ID'] == "Server"):
                print("Valid certificate")
                self.server_pub_key = RSA.importKey(bytes.fromhex(msg['pub_key']))
            else:
                print("Invalid")
        except:
            print("Invalid 2")
        ## Sending Client Public key and Port to get a certificate
        plaintext = dumps({'pub_key': self.pub_key.exportKey().hex(), 'ip': self.ip, 'port': port}).encode()
        key = urandom(16)
        aes_enc_obj = AES.new(key, AES.MODE_ECB)
        ciphertext = aes_enc_obj.encrypt(pad(plaintext, self.BLOCK_SIZE))
        
        rsa_enc_obj = PKCS1_OAEP.new(self.server_pub_key)

        sock.send(dumps({'msg': (ciphertext).hex(), 'msgkey': (rsa_enc_obj.encrypt(key)).hex() }).encode())

        received = loads(sock.recv(8192).decode())

        certificate = bytes.fromhex(received['Certificate'])
        signature = bytes.fromhex(received['Signature'])

        digest = SHA256.new(certificate)
        try:
            pkcs1_15.new(self.CA_pub_key).verify(digest, signature)
            msg = loads(certificate)
            if(bytes.fromhex(msg['pub_key']) == self.pub_key.exportKey() and msg['port'] == self.port and msg['ip'] == self.ip):
                self.ID = msg['ID']
                #print(msg['ip'])
                #print("Certificate received")
                self.certificate = received
                self.getIPTable()
                print("Client "+str(self.ID)+".c6610.uml.edu started")
                start_new_thread(self.start_connect,())
                start_new_thread(self.IPTable_thread,())
                self.start_listen()               
        except Exception as e:
            print(e)
            print("Error 1")

    def IPTable_thread(self):
        while True:
            time.sleep(10)
            try:
                start_new_thread(self.getIPTable,())
            except:
                pass
                
    def getIPTable(self):
        #time.sleep(i)
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.network_ip, self.network_port))
        sock.send(dumps({'requestIPTable': "RequestIPTable"}).encode())
        received = loads(sock.recv(8192).decode())
        #Need to work
        message = bytes.fromhex(received['message'])
        signature = bytes.fromhex(received['signature'])        
        digest = SHA256.new(message)        
        try:
            pkcs1_15.new(self.server_pub_key).verify(digest, signature)
            message = loads(message)            
            if(message['TS'] > self.server_ts):                
                self.server_ts = message['TS']
                iptable = message['iptable']
                self.IPTable = iptable
                del self.IPTable[str(self.ID)]
                print("IPTables updated")
            else:
                print("Timestamp error")
        except Exception as e:
            print(e)
            print("Error in updating IPTable")

    def ping_listener(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.ip, self.port+1))
        sock.listen()
        while True:
            (client, _) = sock.accept()
        
        
    def start_listen(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.bind((self.ip, self.port))
        sock.listen()
        while True:
            (client, _) = sock.accept()
            start_new_thread(self.handle_listen, (client,))

    def handle_listen(self, client):
        client.send(dumps(self.certificate).encode())
        #time.sleep(1)
        received = loads(client.recv(8192))
        Certificate = bytes.fromhex(received['Certificate'])
        Signature = bytes.fromhex(received['Signature'])
        digest = SHA256.new(Certificate)
        try:
            pkcs1_15.new(self.CA_pub_key).verify(digest, Signature)
            msg = loads(Certificate)
            pub_key = RSA.importKey(bytes.fromhex(msg['pub_key']))
            ID = msg['ID']
            received = loads(client.recv(8192))
            Signature = bytes.fromhex(received['signature'])
            received = bytes.fromhex(received['message'])
            rsa_enc_obj = PKCS1_OAEP.new(self.priv_key)
            
            try:
                
                key = rsa_enc_obj.decrypt(received)
                Digest = SHA512.new(key)
                pkcs1_15.new(pub_key).verify(Digest, Signature)

                received = (client.recv(8192)).decode()

                received = bytes.fromhex(received)
                aes_enc_obj = AES.new(key, AES.MODE_ECB)
                try:
                    
                    message = unpad(aes_enc_obj.decrypt(received), self.BLOCK_SIZE)
                    message = loads(message)
                    #print(message['ts'])
                    if(message['ts'] >= time.time()-6):
                        #print("< client"+str(ID)+".c6610.uml.edu: "+ message['message'])
                        if(message['message'] == "PING"):
                            plaintext = dumps({'message': "PONG", 'ts': time.time()}).encode()
                            
                            aes_enc_obj = AES.new(key, AES.MODE_ECB)
                            ciphertext = aes_enc_obj.encrypt(pad(plaintext, self.BLOCK_SIZE))
                            ciphertext = (ciphertext).hex()
                            client.send((ciphertext).encode())
                            #print("> client"+str(ID)+".c6610.uml.edu: PONG")
                except:
                    print("Error 3")
                
            except Exception as e:
                print(e)
            
            
        except Exception as e:
            print(e)
            print("Certificate verification failed 1")
            
        pass

    def start_connect(self):
        #print("hi111")
        while True:
            for i in self.IPTable.keys():
                start_new_thread(self.handle_connect, (i,))
            time.sleep(15)
        

    def handle_connect(self, ID):
        sock = socket(AF_INET, SOCK_STREAM)
        
        try:
            ip, port = (self.IPTable[ID]).split(":")
            sock.connect((ip, int(port)))
            ##2nd receive
            received = loads(sock.recv(8192))

            Certificate = bytes.fromhex(received['Certificate'])
            Signature = bytes.fromhex(received['Signature'])

            digest = SHA256.new(Certificate)
            
            try:
                pkcs1_15.new(self.CA_pub_key).verify(digest, Signature)
                msg = loads(Certificate)
                if(msg['ID'] == int(ID) and msg['port'] == int(port)):
                    pub_key = RSA.importKey(bytes.fromhex(msg['pub_key']))
                    sock.send(dumps(self.certificate).encode())
                    key = urandom(16)
                    rsa_enc_obj = PKCS1_OAEP.new(pub_key)
                    Digest = SHA512.new(key)
                    signature = pkcs1_15.new(self.priv_key).sign(Digest)
                    sock.send(dumps({'message': rsa_enc_obj.encrypt(key).hex(), 'signature': signature.hex()}).encode())
                    plaintext = dumps({'message': "PING", 'ts': time.time()}).encode()
                    aes_enc_obj = AES.new(key, AES.MODE_ECB)
                    ciphertext = aes_enc_obj.encrypt(pad(plaintext, self.BLOCK_SIZE))
                    ciphertext = (ciphertext).hex()
                    sock.send((ciphertext).encode())
                    print("> client"+str(ID)+".c6610.uml.edu: PING")

                    time.sleep(1)
                    received = (sock.recv(8192)).decode()
                    received = bytes.fromhex(received)
                    
                    aes_enc_obj = AES.new(key, AES.MODE_ECB)
                    try:
                        message = unpad(aes_enc_obj.decrypt(received), self.BLOCK_SIZE)
                        message = loads(message)
                        if(message['ts'] >= time.time()-6):
                            print("< client"+str(ID)+".c6610.uml.edu: "+ message['message'])
                    except:
                        pass
                            
                    
            except Exception as e:
                print(e)
                print("Certificate verification failed 2")
        except Exception as e:
            print(e)
            print("Error")

if __name__ == '__main__':
    sip, sport = (sys.argv[1]).split(":")


    
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    tip = s.getsockname()[0]
    sock = socket(AF_INET, SOCK_STREAM)
    port = 9500
    while 1:
        try:
            sock.bind((tip, port))
            s = socket(AF_INET, SOCK_STREAM)
            s.bind((tip, port+1))
            s.close()
            
            break
        except:
            port += 4
    sock.close()
    client = Client(sip, sport, tip, port)
