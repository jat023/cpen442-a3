#!/usr/bin/env python3

def get_connect_info_from_user():
    ip = input('Input IP: ').strip()
    port = input('Input port: ').strip()

    return (ip, int(port))
