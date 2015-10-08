#!/usr/bin/env python3
import socket

def get_connect_info_from_user():
    port = input('Input port: ').strip()
    return int(port)
