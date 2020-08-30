#!/usr/bin/env python3
import socket
import json
import sys
import threading
import copy
import time
import yaml
import psycopg2
import radius_server

def send_config(ovsdb_conn, command):
    '''does a single OVSDB transaction'''
    print("sending ", command)
    ovsdb_conn.send(json.dumps(command).encode('utf-8'))
    returned = ovsdb_conn.recv(2048).decode("utf-8")
    print(returned)
    return json.loads(returned)

def config_ap(config, ovsdb_conn, sql_conn):
    '''configures an individual AP'''
    #send interface configs
    for interface in config['interfaces']:
        print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Inet_Config","row":interface}], "id": 0}))

    #sends config for custom openflow controller
    if 'openflow-controller' in config:
        print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Inet_Config", \
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
        data = send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_VIF_Config","row":network}, {"op": "insert","table": "Wifi_VIF_State","row":network}], "id": 0})
        print(data)
        if enabled:
            wlan_enabled.append(data['result'][0]['uuid'][1])
        vif_configs.setdefault(network['if_name'],["uuid"]).append(data['result'][0]['uuid'][1])

    print(vif_configs)

    for wlan_interface in config['wlan_interfaces']:
        print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_State","row": wlan_interface}], "id": 0}))
        if wlan_interface['if_name'] in vif_configs:
            wlan_interface['vif_configs'] = vif_configs[wlan_interface['if_name']]
        print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op": "insert","table": "Wifi_Radio_Config","row": wlan_interface}], "id": 0}))

    for uuid in wlan_enabled:
        print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "Wifi_VIF_Config", "where": [["_uuid", "==", ["uuid",uuid]]], "row": {"enabled":True}}], "id": 0}))

    print(send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"update", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]], "row": {"upgrade_status":1}}], "id": 0}))

    for network in config['wifi_networks']:
        print("looking for" , network['if_name'])
        result = send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "Wifi_Inet_State", "where": [["if_name", "==", network['if_name']]]}], "id": 0})['result'][0]['rows']
        while result == []:
            time.sleep(0.5)
            result = send_config(ovsdb_conn,{"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "Wifi_Inet_State", "where": [["if_name", "==", network['if_name']]]}], "id": 0})['result'][0]['rows']
        ap_user_name = result[0]['hwaddr'].upper().replace(':', '-') + ":" + network['ssid']
        print(ap_user_name, ',',default_password)
        radius_server.add_login_db(ap_user_name, default_password, sql_conn)
    #sql_conn.commit()
    ovsdb_conn.close()


def config_aps(config, ovsdb_conn, addr):
    '''finds the right config for an AP and calls config_ap to configure it'''
    sql_conn = psycopg2.connect(host=config['postgresql_db']['address'],dbname=config['postgresql_db']['dbname'], user=config['postgresql_db']['user'], password=config['postgresql_db']['password'])
    with ovsdb_conn:
        data = send_config(ovsdb_conn, {"method":"transact", "params":[ "Open_vSwitch", {"op":"select", "table": "AWLAN_Node", "where": [["upgrade_status", "==", 0]]}], "id": 0})
        if data['result'][0]['rows'] != []:
            ap_hostname = data['result'][0]['rows'][0]['id']
            print('Connection from ', ap_hostname, 'at ', addr)
            if ap_hostname in config['access_points'].keys():
                print('configuring ', ap_hostname, ' with custom config')
                config_ap(copy.deepcopy(config['access_points'][ap_hostname]), ovsdb_conn, sql_conn)
            elif 'default' in  config['access_points'].keys():
                print('configuring ', ap_hostname, ' with default config')
                config_ap(copy.deepcopy(config['access_points']['default']), ovsdb_conn, sql_conn)
            else:
                print('error: no custom or defaul config exists for ', ap_hostname)

if len(sys.argv) != 2:
    print("usage: controller <config file>")
    sys.exit()

with open(sys.argv[1], 'r') as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
        sys.exit()

radius_thread = threading.Thread(target=radius_server.RadiusServer, args=(config['postgresql_db'],radius_server.dictionary.Dictionary("dictionary"),))
radius_thread.start()

controller_threads = []

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('',6640))
socket.listen(0)
while True:
    ovsdb_conn, addr = socket.accept()
    controller_threads.append(threading.Thread(target=config_aps, args=(config, ovsdb_conn, addr,)))
    controller_threads[len(controller_threads)-1].start()
