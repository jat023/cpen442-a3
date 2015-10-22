#!/usr/bin/env python3
import sys
import client
import server
import socket
import time
import session
import string
import random
from config import PRIME, GENERATOR


BUFFER_SIZE = 1024  
AUTHENTICATED = False

while True:
    mode = input('Open in (C)lient or (S)erver mode?: ').strip().upper()
    if mode != 'C' and mode != 'S':
        print('Invalid value. Try again.')
    else: break

if mode == 'C':
    ip, port = client.get_connect_info_from_user()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    secret_key = input('Enter the shared secret key: ').strip()

    #Authentication
    print("Starting Authentication")
    client = session.Session(secret_key)
    client_nonce = client.send_plaintext_nonce()
    s.send(client_nonce)
    data = s.recv(BUFFER_SIZE)
    clients_nonce_encrypted_by_server = data
    clients_nonce_and_servers_remainder_decrypted_by_client, servers_nonce = client.decrypt_nonce(clients_nonce_encrypted_by_server)
    servers_nonce_encrypted_by_client = client.encrypt_nonce(servers_nonce)
    s.send(servers_nonce_encrypted_by_client)
    client.set_session_key(clients_nonce_and_servers_remainder_decrypted_by_client)

    #Server Challenge Client
    data = s.recv(BUFFER_SIZE)
    challenge_plaintext = data.decode('utf-8')
    challenge_cryptotext = client.encrypt(challenge_plaintext)
    s.send(challenge_cryptotext)
    data = s.recv(BUFFER_SIZE)
    auth_response = data.decode('utf-8')

    #Client Challenge Server
    chars = string.ascii_letters + string.digits + string.punctuation
    pwdSize = 8
    random_client_challenge = ''.join((random.choice(chars)) for x in range(pwdSize))

    s.send(random_client_challenge.encode('utf-8'))
    server_challenge_response = s.recv(BUFFER_SIZE)
    client_cryptotext = client.encrypt(random_client_challenge)

    if  server_challenge_response == client_cryptotext:
        s.send("AUTHENTICATION SUCCESSFUL".encode('utf-8'))
    else: 
        s.send("AUTHENTICATION FAILED".encode('utf-8'))

    print("*******************************")
    print("==========SESSION INFO=========")
    print("GENERATOR: \n" + str(GENERATOR))
    print("-------------------------------")
    print("PRIME NUMBER: \n" + str(PRIME))
    print("-------------------------------")
    print("CLIENT SECRET VALUE: \n" + str(client.my_nonce))
    print("-------------------------------")
    print("CLIENT SESSION KEY: \n" + client.session_key)
    print("-------------------------------")
    print("CLIENT RANDOM CHALLENGE \n" + random_client_challenge)
    print("-------------------------------")   
    print("SERVER CHALLENGE RESPONSE \n" + server_challenge_response.decode('utf-8'))
    print("-------------------------------")
    print("CLIENT CHALLENGE ANSWER \n" + client_cryptotext.decode('utf-8'))
    print("-------------------------------")
    if server_challenge_response == client_cryptotext:
        print("-----Client Challenge Server Successfull-----")
        AUTHENTICATED = True
    else:
        print("-----Client Challenge Server Failed-----")
        AUTHENTICATED = False
    print("==============END==============")
    print("*******************************")
    print(auth_response)

    while AUTHENTICATED:
        message = input('Data to be sent (Plaintext): ').strip()
        encryptedMessage = client.encrypt(message)
        s.send(encryptedMessage)
        print('Data Sent (Ciphertext): ' + str(encryptedMessage))
        print("-------------------------------")

if mode == 'S':
    port = server.get_connect_info_from_user()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), port))
    s.listen(1)

    secret_key = input('Enter the shared secret key: ').strip()

    print("Started server on %s" % socket.gethostname() + ":" + str(port))


    connection, addr = s.accept()

    print("Connected to {}".format(addr))

    #Authentication
    server = session.Session(secret_key)
    data = connection.recv(BUFFER_SIZE)
    client_nonce = data
    clients_nonce_encrypted_by_server = server.encrypt_nonce(client_nonce)
    connection.send(clients_nonce_encrypted_by_server)
    data = connection.recv(BUFFER_SIZE)
    servers_nonce_encrypted_by_client = data
    servers_nonce_and_clients_remainder_decrypted_by_server = server.decrypt_nonce(servers_nonce_encrypted_by_client)[0]
    server.set_session_key(servers_nonce_and_clients_remainder_decrypted_by_server)

    #Server challenge client
    chars = string.ascii_letters + string.digits + string.punctuation
    pwdSize = 8
    random_server_challenge = ''.join((random.choice(chars)) for x in range(pwdSize))

    connection.send(random_server_challenge.encode('utf-8'))

    client_challenge_response = connection.recv(BUFFER_SIZE)
    server_cryptotext = server.encrypt(random_server_challenge)

    if  client_challenge_response == server_cryptotext:
        connection.send("AUTHENTICATION SUCCESSFUL".encode('utf-8'))
    else: 
        connection.send("AUTHENTICATION FAILED".encode('utf-8'))

    #Client Challenge Server
    data = connection.recv(BUFFER_SIZE)
    challenge_plaintext = data.decode('utf-8')
    challenge_cryptotext = server.encrypt(challenge_plaintext)
    connection.send(challenge_cryptotext)

    data = connection.recv(BUFFER_SIZE)
    auth_response = data.decode('utf-8')

    print("*******************************")
    print("==========SESSION INFO=========")
    print("GENERATOR: \n" + str(GENERATOR))
    print("-------------------------------")
    print("PRIME NUMBER: \n" + str(PRIME))
    print("-------------------------------")
    print("SERVER SECRET VALUE: \n" + str(server.my_nonce))
    print("-------------------------------")
    print("SERVER SESSION KEY: \n" + server.session_key)
    print("-------------------------------")
    print("SERVER RANDOM CHALLENGE: \n" + random_server_challenge)
    print("-------------------------------")
    print("CLIENT CHALLENGE RESPONSE: \n" + client_challenge_response.decode('utf-8'))
    print("-------------------------------")
    print("SERVER CHALLENGE ANSWER \n" + server_cryptotext.decode('utf-8'))
    print("-------------------------------")
    if client_challenge_response == server_cryptotext:
        print("-----Server Challenge Client Successfull-----")
        AUTHENTICATED = True
    else:
        print("-----Server Challenge Client Failed-----")
        AUTHENTICATED = False
    print("==============END==============")
    print("*******************************")
    print(auth_response)


    while AUTHENTICATED:
        data = connection.recv(BUFFER_SIZE)
        if not data: break
        print('Data as Recieved (Ciphertext): ', data)
        message = server.decrypt(data)
        print('Data decrypted (Plaintext): ', message)
        print("-------------------------------")

    connection.close()
