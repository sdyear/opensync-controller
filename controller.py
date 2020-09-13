#!/usr/bin/env python3
import socket
import sys
import threading
import yaml
import radius_server
import ap

if len(sys.argv) != 3:
    print("usage: controller <config file> <port>")
    sys.exit()

try:
    port_num = int(sys.argv[2])
    assert 0 < port_num <= 65535
    
except (ValueError, AssertionError):
    print("error:", sys.argv[2], " is not a valid port number")
    print("usage: controller <config file> <port>")
    sys.exit()

with open(sys.argv[1], 'r') as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:

        print(exc)
        sys.exit()

#starts radius server tread
radius_thread = threading.Thread(
    target=radius_server.RadiusServer,
    args=(config['postgresql_db'],radius_server.dictionary.Dictionary("dictionary"),))
radius_thread.start()

#starts socket to listen for connecting APs and generates 
# an AP object for each connection to configre each AP
controller_threads = []
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('',port_num))
socket.listen(0)
while True:
    ovsdb_conn, addr = socket.accept()
    controller_threads.append(threading.Thread(target=ap.AP, args=(config, ovsdb_conn, addr,)))
    controller_threads[len(controller_threads)-1].start()
