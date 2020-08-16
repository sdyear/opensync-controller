#!/usr/bin/env python3
import socket
import json
import sys
import yaml
import threading

def configure(config, conn, addr):
	with conn:
		conn.send(json.dumps({"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]]}], "id": 0}).encode('utf-8'))
		data = json.loads(conn.recv(2048).decode("utf-8"))
		if data['result'][0]['rows'] != []:
			print('Connected by', addr)

			for interface in config['interfaces']:
				command =  {"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Inet_Config","row":interface}], "id": 0}
				print(command)
				conn.send(json.dumps(command).encode('utf-8'))
				data = json.loads(conn.recv(1024).decode("utf-8"))
				print(data)

			print(config['wifi_networks'])
			wlan_enabled = []
			vif_configs = {}
			for network in config['wifi_networks']:
				enabled = network['enabled']
				network['enabled'] = False
				security = ["map", []]
				for item in network['security']:
					security[1].append([list(item.keys())[0],str(list(item.values())[0])])
				print(security)
				network['security'] = security
				command =  {"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_VIF_Config","row":network}, {"op": "insert","table": "Wifi_VIF_State","row":network}], "id": 0}
				print(command)
				conn.send(json.dumps(command).encode('utf-8'))
				data = json.loads(conn.recv(1024).decode("utf-8"))
				print(data)
				if enabled:
					wlan_enabled.append(data['result'][0]['uuid'][1])
				vif_configs.setdefault(network['if_name'],["uuid"]).append(data['result'][0]['uuid'][1])

			print(vif_configs)

			for wlan_interface in config['wlan_interfaces']:
				command =  {"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_State","row": wlan_interface}], "id": 0}
				print(command)
				conn.send(json.dumps(command).encode('utf-8'))
				data = json.loads(conn.recv(1024).decode("utf-8"))
				print(data)
				if wlan_interface['if_name'] in vif_configs:
					wlan_interface['vif_configs'] = vif_configs[wlan_interface['if_name']]
				command =  {"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_Config","row": wlan_interface}], "id": 0}
				print(command)
				conn.send(json.dumps(command).encode('utf-8'))
				data = json.loads(conn.recv(1024).decode("utf-8"))
				print(data)

			for uuid in wlan_enabled:
				command =  {"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "Wifi_VIF_Config", "where": [["_uuid", "==", ["uuid",uuid]]], "row": {"enabled":True}}], "id": 0}
				print(command)
				conn.send(json.dumps(command).encode('utf-8'))
				data = json.loads(conn.recv(1024).decode("utf-8"))
				print(data)

			command =  {"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]], "row": {"upgrade_status":1}}], "id": 0}
			print(command)
			conn.send(json.dumps(command).encode('utf-8'))
			data = json.loads(conn.recv(1024).decode("utf-8"))
			print(data)

if(len(sys.argv)!=2):
	print("usage: controller <config file>")
	exit(-1)

with open(sys.argv[1], 'r') as stream:
	try:
		config = yaml.safe_load(stream)
	except yaml.YAMLError as exc:
		print(exc)
		exit(-1)

controller_threads = []

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('',6640))
socket.listen(0)
while True:
	conn, addr = socket.accept()
	controller_threads.append(threading.Thread(target=configure, args=(config, conn, addr,)))
	controller_threads[len(controller_threads)-1].start()