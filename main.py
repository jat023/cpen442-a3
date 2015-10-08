#!/usr/bin/env python3
import sys
import client
import server
import socket
import time

BUFFER_SIZE = 1024

while True:
    mode = input('Open in (C)lient or (S)erver mode?: ').strip().upper()
    if mode != 'C' and mode != 'S':
        print('Invalid value. Try again.')
    else: break

if mode == 'C':
    ip, port = client.get_connect_info_from_user()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    message = input('Message to send: ').strip().encode('ascii')
    print("Message to be sent: {}".format(message))
    s.sendall(message)
    data = s.recv(BUFFER_SIZE)
    s.close()
    print('Received', repr(data))

if mode == 'S':
    port = server.get_connect_info_from_user()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), port))
    s.listen(1)

    print("Started server on %s" % socket.gethostname())

    connection, addr = s.accept()

    print("Connected to {}".format(addr))
    while True:
        data = connection.recv(BUFFER_SIZE)
        if not data: break
        currentTime = time.ctime(time.time()) + "\r\n"
        print('Received', repr(data))
        connection.sendall(currentTime.encode('ascii'))

    connection.close()
