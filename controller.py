#!/usr/bin/env python3
import socket
import json
import sys
import yaml
import threading
from pyrad import dictionary, packet, server, client
import pdb
import psycopg2
import struct
import hashlib
import copy
import time

def build_tunnel_password(secret, authenticator, psk):
	a = b"\xab\xcd"
	psk = psk.encode()
	padlen = 16 - (1 + len(psk)) % 16
	if padlen == 16:
		padlen = 0
	p = struct.pack('B', len(psk)) + psk + padlen * b'\x00'
	cc_all = bytes()
	b = hashlib.md5(secret + authenticator + a).digest()
	while len(p) > 0:
		pp = bytearray(p[0:16])
		p = p[16:]
		bb = bytearray(b)
		cc = bytearray(pp[i] ^ bb[i] for i in range(len(bb)))
		cc_all += cc
		b = hashlib.md5(secret + cc).digest()
	data = b'\x00' + a + bytes(cc_all)
	return data

def get_next_id(cur):
	#find the next avaliable id number to use for the device
	cur.execute("SELECT id FROM radcheck ORDER BY id")
	result = cur.fetchall()
	if len(result) == 0:
		return '0'
	elif len(result) == 1:
		return str(result[0][0]+1)
	else:
		return str(result[len(result)-1][0]+2)

class RadiusServer(server.Server):

	def __init__(self, sql_config, dict):
		super().__init__(dict=dict)
		self.sql_conn =  psycopg2.connect(host=sql_config['address'],dbname=sql_config['dbname'], user=sql_config['user'], password=sql_config['password'])
		self.hosts["0.0.0.0"] = server.RemoteHost("0.0.0.0", b"secret", "ap10")
		self.BindToAddress("0.0.0.0")
		self.Run()


	def HandleAuthPacket(self, pkt):
		print("Received an authentication request")
		print("Attributes: ")
		for attr in pkt.keys():
			print("%s: %s" % (attr, pkt[attr]))
		#checks if connecting device is in the db
		cur = self.sql_conn.cursor()
		cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
		result = cur.fetchone()
		#if it's in the db and the password is correct
		if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
			print("the device is known")
			#get the tunnel-password for that device
			cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply WHERE Username = '" + pkt['User-Name'][0] + "' ORDER BY id")
			#reply with the tunnel password as an attribute
			reply = self.CreateReplyPacket(pkt)
			data = build_tunnel_password(reply.secret, pkt.authenticator, cur.fetchone()[3])
			reply.AddAttribute("Tunnel-Password", data)
			reply.code = packet.AccessAccept
			reply.add_message_authenticator()
			self.SendReplyPacket(pkt.fd, reply)
		#the device isn't in the db
		else:
			print("the device is unknown")
			#look up the AP the device connected to in the db
			print("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
			cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
			result = cur.fetchone()
			#if the ap is in the db
			if result is not None and result[3]==pkt['Called-Station-Id'][0]:
				print("the AP is known")
				#get the tunnel-password for that ap
				cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
				tunnel_password = cur.fetchone()[3]
				newId = get_next_id(cur)
				#add the device to the db giving it the tunnel-password for the ap it connected to
				cur.execute("INSERT INTO radcheck VALUES (" + newId + ", '" + str(pkt[1][0],'utf-8') + "', 'Cleartext-Password', ':=', '" + str(pkt[1][0],'utf-8') +"')")
				cur.execute("INSERT INTO radreply VALUES (" + newId + ", '" + str(pkt[1][0],'utf-8') + "', 'Tunnel-Password', ':=', '" + tunnel_password +"')")
				self.sql_conn.commit()
				#look for the device in the db again
				cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
				result = cur.fetchone()
				print(result)
				#if the device is now in the db
				if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
					print("the deive is now known")
					#get the tunnel password for the device
					cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply WHERE Username = '" + pkt['User-Name'][0] + "' ORDER BY id")
					#send a radius reply with the tunnel password as an attribute
					reply = self.CreateReplyPacket(pkt)
					data = build_tunnel_password(reply.secret, pkt.authenticator, cur.fetchone()[3])
					reply.AddAttribute("Tunnel-Password", data)
					reply.code = packet.AccessAccept
					reply.add_message_authenticator()
					self.SendReplyPacket(pkt.fd, reply)
				else:
					print("adding device failed")
			else:
				print('aps is unknown')

def send_config(conn, command):
		#print(command)
		conn.send(json.dumps(command).encode('utf-8'))
		returned = conn.recv(2048).decode("utf-8")
		print(returned)
		return json.loads(returned)
		
def config_ap(config, conn, sql_conn):
	for interface in config['interfaces']:
		print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Inet_Config","row":interface}], "id": 0}))

	if 'openflow-controller' in config:
		print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Inet_Config", \
			"row":{"if_name":"bridge", "if_type":"bridge","enabled":True, "network":True, \
			"controller_address":config['openflow-controller']['address'], "datapath_id":config['openflow-controller']['datapath-id']}}], "id": 0}))

	wlan_enabled = []
	vif_configs = {}
	default_password = ''
	for network in config['wifi_networks']:
		enabled = network['enabled']
		network['enabled'] = False
		security = ["map", []]
		print(network['security'])
		for item in network['security']:
			if list(item.keys())[0] != 'default_password':
				security[1].append([list(item.keys())[0],str(list(item.values())[0])])
			else:
				default_password = str(list(item.values())[0])
		print(security)
		network['security'] = security
		data = send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_VIF_Config","row":network}, {"op": "insert","table": "Wifi_VIF_State","row":network}], "id": 0})
		print(data)
		if enabled:
			wlan_enabled.append(data['result'][0]['uuid'][1])
		vif_configs.setdefault(network['if_name'],["uuid"]).append(data['result'][0]['uuid'][1])

	print(vif_configs)

	for wlan_interface in config['wlan_interfaces']:
		print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_State","row": wlan_interface}], "id": 0}))
		if wlan_interface['if_name'] in vif_configs:
			wlan_interface['vif_configs'] = vif_configs[wlan_interface['if_name']]
		print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_Config","row": wlan_interface}], "id": 0}))

	for uuid in wlan_enabled:
		print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "Wifi_VIF_Config", "where": [["_uuid", "==", ["uuid",uuid]]], "row": {"enabled":True}}], "id": 0}))

	print(send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]], "row": {"upgrade_status":1}}], "id": 0}))
	
	for network in config['wifi_networks']:
		print("looking for" , network['if_name'])
		result = send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "Wifi_Inet_State", "where": [["if_name", "==", network['if_name']]]}], "id": 0})['result'][0]['rows']
		while result == []:
			time.sleep(0.5)
			result = send_config(conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "Wifi_Inet_State", "where": [["if_name", "==", network['if_name']]]}], "id": 0})['result'][0]['rows']
		ap_user_name = result[0]['hwaddr'].upper().replace(':', '-') + ":" + network['ssid']
		print(ap_user_name, ',',default_password)
		cur = sql_conn.cursor()
		#find the next avaliable id number to use for the device
		newId = get_next_id(cur)
		cur.execute("SELECT * FROM radcheck WHERE Username = '" + ap_user_name + "'")
		result = cur.fetchone()
		#if the ap is in the db
		if result is None:
			print("INSERT INTO radcheck VALUES (" + newId + ", '" + ap_user_name + "', 'Cleartext-Password', ':=', '" + ap_user_name +"')")
			cur.execute("INSERT INTO radcheck VALUES (" + newId + ", '" + ap_user_name + "', 'Cleartext-Password', ':=', '" + ap_user_name +"')")
			print("INSERT INTO radreply VALUES (" + newId + ", '" + ap_user_name + "', 'Tunnel-Password', ':=', '" + default_password +"')")
			cur.execute("INSERT INTO radreply VALUES (" + newId + ", '" + ap_user_name + "', 'Tunnel-Password', ':=', '" + default_password +"')")
		sql_conn.commit()


def config_aps(config, conn, addr):
	sql_conn = psycopg2.connect(host=config['postgresql_db']['address'],dbname=config['postgresql_db']['dbname'], user=config['postgresql_db']['user'], password=config['postgresql_db']['password'])
	with conn:
		data = send_config(conn, {"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]]}], "id": 0})
		if data['result'][0]['rows'] != []:
			ap_hostname = data['result'][0]['rows'][0]['id']
			print('Connection from ', ap_hostname, 'at ', addr)
			if ap_hostname in config['access_points'].keys():
				print('configuring ', ap_hostname, ' with custom config')
				config_ap(copy.deepcopy(config['access_points'][ap_hostname]), conn, sql_conn)
			elif 'default' in  config['access_points'].keys():
				print('configuring ', ap_hostname, ' with default config')
				config_ap(copy.deepcopy(config['access_points']['default']), conn, sql_conn)
			else:
				print('error: no custom or defaul config exists for ', ap_hostname)

if(len(sys.argv)!=2):
	print("usage: controller <config file>")
	exit(-1)

with open(sys.argv[1], 'r') as stream:
	try:
		config = yaml.safe_load(stream)
	except yaml.YAMLError as exc:
		print(exc)
		exit(-1)

#radius_thread = threading.Thread(target=start_radius, args=(config['postgresql_db'],))
#radius_thread.start()

radius_thread = threading.Thread(target=RadiusServer, args=(config['postgresql_db'],dictionary.Dictionary("dictionary"),))
radius_thread.start()
RadiusServer

controller_threads = []

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('',6640))
socket.listen(0)
while True:
	conn, addr = socket.accept()
	controller_threads.append(threading.Thread(target=config_aps, args=(config, conn, addr,)))
	controller_threads[len(controller_threads)-1].start()