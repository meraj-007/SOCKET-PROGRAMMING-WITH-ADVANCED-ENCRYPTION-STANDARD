# Python program to implement client side of chat room. 
import socket 
import select 
import sys 
from Crypto.Cipher import AES
import math
import base64

key = input("What is the key?")
if len(key) < 16:
    counter = 0
    while len(key) != 16:
        counter += 1
        key += str(counter)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
if len(sys.argv) != 3: 
    print ("Correct usage: script, IP address, port number")
    exit() 
IP_address = str(sys.argv[1]) 
Port = int(sys.argv[2]) 
server.connect((IP_address, Port))

def encrypt(privateInfo, key):
    BlockSize = 16
    padding = '{'
    pad = lambda s: s + ((BlockSize - (len(s) % BlockSize)) * padding)

    cipher = AES.new(key)
    x = pad(privateInfo)
    # print(len(x), x)
    encoded = base64.b64encode(cipher.encrypt(x))
    # print ("Encrypted String: ", encoded)
    return encoded

def decrypt(encryptedString, key):
    padding = '{'
    # print(encryptedString, len(encryptedString))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))
    cipher = AES.new(key)
    decoded = DecodeAES(cipher, encryptedString)
    decoded = decoded.decode().rstrip(padding)

    return decoded 
  
while True: 
  
    # maintains a list of possible input streams 
    sockets_list = [sys.stdin, server] 
  
    """ There are two possible input situations. Either the 
    user wants to give  manual input to send to other people, 
    or the server is sending a message  to be printed on the 
    screen. Select returns from sockets_list, the stream that 
    is reader for input. So for example, if the server wants 
    to send a message, then the if condition will hold true 
    below.If the user wants to send a message, the else 
    condition will evaluate as true"""
    read_sockets,write_socket, error_socket = select.select(sockets_list,[],[]) 
  
    for socks in read_sockets: 
        if socks == server: 
            message = socks.recv(2048) 
            # message = message.decode().encode('ascii',errors='ignore')
            #print (message)
            if message == b"Welcome to this chatroom!":
                print (message)
            else:
                # print("Decrypting...")
                # print(f'without decoding = {message}')
                message = str(message)
                message = message[2:-1]
                # print(f'with decoding = {message}')
                user = message[:message.index('~')]
                msg = message[message.index('~') + 1:]
                # print("1 -> ", msg, type(msg))
                # msg = b"" + msg.encode()
                # print("2 -> ", msg, type(msg))
                # message[1] = message[1][2: -1]
                # message[1] = message[1].encode()
                # print(user, msg)
                # print(decrypt(msg, key))
                try:
                    print(user, decrypt(msg, key))
                except:
                    print("Error, key not matched")
                    print("Encrypted message is ", msg)
                # print (message[0],decrypt(message[1], key))
        else: 
            message = sys.stdin.readline() 
            server.send(encrypt(message, key))
            # sys.stdout.write("<You>") 
            # sys.stdout.write(message) 
            sys.stdout.flush() 
server.close() 