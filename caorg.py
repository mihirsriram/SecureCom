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



class CA:
    def __init__(self, ip, port):
        self.port = port
        self.ip = ip
        self.priv_key = RSA.generate(2048)
        self.pub_key = self.priv_key.public_key()

        self.BLOCK_SIZE = 32

        fo = open("CAPublicKey.txt", 'wb')
        fo.write(self.pub_key.exportKey())
        fo.close()

        self.server_contact_flag = 0
        

    def start(self):
        sock = socket(AF_INET, SOCK_STREAM)
        #sock.bind(('0.0.0.0', self.port))
        sock.bind((self.ip, self.port))
        sock.listen()
        print("Certificate Authority started at: "+self.ip+":"+str(self.port))
        while True:
            (client, _) = sock.accept()
            start_new_thread(self.handle_request, (client,))

    def handle_request(self, client):
        received = loads(client.recv(8192).decode())
        try:
            if self.server_contact_flag == 0:
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
                msg = loads(msg)
                
                if "flag" in msg.keys():
                    pub_key = bytes.fromhex(msg['key'])
                    Certificate = dumps({'pub_key': pub_key.hex(), 'ID': "Server"}).encode()
                    digest = SHA256.new(Certificate)            
                    signature = pkcs1_15.new(self.priv_key).sign(digest)

                    client.send(dumps({'Certificate': (Certificate).hex(), 'Signature': (signature).hex()}).encode())
                    self.server_contact_flag = 1
                            
            else:
                
                server_cert = received['certificate']
                
                Certificate = bytes.fromhex(server_cert['Certificate'])
                Signature = bytes.fromhex(server_cert['Signature'])
                digest = SHA256.new(Certificate)
                try:
                    pkcs1_15.new(self.pub_key).verify(digest, Signature)
                    msg = loads(Certificate)                
                    if(msg['ID'] == "Server"):
                        pub_key = RSA.importKey(bytes.fromhex(msg['pub_key']))
                        message = bytes.fromhex(received['message'])
                        signature = bytes.fromhex(received['signature'])

                        digest = SHA256.new(message)
                        try:
                            pkcs1_15.new(pub_key).verify(digest, signature)
                            digest = SHA256.new(message)
                            signature = pkcs1_15.new(self.priv_key).sign(digest)
                            client.send(dumps({'Certificate': (message).hex(), 'Signature': (signature).hex()}).encode())                            
                        except Exception as e:
                            pass
                
                except Exception as e:
                    pass
        except:
            pass

if __name__ == '__main__':
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    tip = s.getsockname()[0]
    #print(tip)
    server = CA(tip, port=9000)
    server.start()
