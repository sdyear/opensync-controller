""" this module is used to configure OpenSync on APs """
import json
import copy
import time
import psycopg2
import radius_server

class AP:
    '''configures OpenSync on an AP'''
    def __init__(self, config, ovsdb_conn, addr):
        '''finds the right config for an AP and calls config_ap to configure it'''
        self.sql_conn = psycopg2.connect(host=config['postgresql_db']['address'],
            dbname=config['postgresql_db']['dbname'],
            user=config['postgresql_db']['user'],
            password=config['postgresql_db']['password'])
        self.config = config
        self.ovsdb_conn = ovsdb_conn
        awlan_node_column = self.ovsdb_select("AWLAN_Node", [['upgrade_status', '==', 0]])
        if awlan_node_column['result'][0]['rows'] != []:
            ap_hostname = awlan_node_column['result'][0]['rows'][0]['id']
            print('Connection from ', ap_hostname, 'at ', addr)
            if ap_hostname in config['access_points'].keys():
                print('configuring ', ap_hostname, ' with custom config')
                self.config_ap(copy.deepcopy(config['access_points'][ap_hostname]))
            elif 'default' in  config['access_points'].keys():
                print('configuring ', ap_hostname, ' with default config')
                self.config_ap(copy.deepcopy(config['access_points']['default']))
            else:
                print('error: no custom or defaul config exists for ', ap_hostname)
        self.ovsdb_conn.close()

    def send_config(self, command):
        '''performs a single OVSDB transaction'''
        print("sending ", command)
        self.ovsdb_conn.send(json.dumps(command).encode('utf-8'))
        returned = json.loads(self.ovsdb_conn.recv(2048).decode("utf-8"))
        if returned['error'] is not None:
            print("error:", returned)
        return returned

    def ovsdb_insert(self, table, row):
        """inserts a row of data in ovsdb"""
        return self.send_config({"method":"transact",
            "params":
                [ "Open_vSwitch",
                        {"op": "insert", "table": table, "row":row}],
            "id": 0})

    def ovsdb_select(self, table, where):
        """selects a row of data in ovsdb"""
        return self.send_config({"method":"transact",
            "params":
            [ "Open_vSwitch",
                    {"op":"select",
                    "table": table,
                    "where": where}],
            "id": 0})

    def ovsdb_update(self, table, where, row):
        """updates a row of data in ovsdb"""
        return self.send_config({"method":"transact",
            "params":
                [ "Open_vSwitch",
                       {"op":"update", "table": table, "where": where, "row": row}],
            "id": 0})

    def config_ap(self, config):
        '''configures an individual AP'''
        #send interface configs
        print("configuring interfaces")
        for interface in config['interfaces']:
            self.ovsdb_insert("Wifi_Inet_Config", interface)

        #sends config for custom openflow controller
        if 'openflow-controller' in config:
            print("configuring openflow controller")
            self.ovsdb_insert("Wifi_Inet_Config",
                {"if_name":"bridge",
                "if_type":"bridge",
                "enabled":True,
                "network":True,
                "controller_address":config['openflow-controller']['address'],
                "datapath_id":config['openflow-controller']['datapath-id']})

        print("configuring WLAN")
        wlan_enabled = []
        vif_configs = {}
        default_password = ''
        for network in config['wifi_networks']:
            enabled = network['enabled']
            network['enabled'] = False
            security = ["map", []]
            for item in network['security']:
                if list(item.keys())[0] != 'default_password':
                    security[1].append([list(item.keys())[0],str(list(item.values())[0])])
                else:
                    default_password = str(list(item.values())[0])
            network['security'] = security
            data = self.ovsdb_insert("Wifi_VIF_Config", network)
            self.ovsdb_insert("Wifi_VIF_State", network)
            if enabled:
                wlan_enabled.append(data['result'][0]['uuid'][1])
            vif_configs.setdefault(network['if_name'],["uuid"]).append(data['result'][0]['uuid'][1])

        print("configuring WLAN interfaces")
        for wlan_interface in config['wlan_interfaces']:
            self.ovsdb_insert("Wifi_Radio_State", wlan_interface)
            if wlan_interface['if_name'] in vif_configs:
                wlan_interface['vif_configs'] = vif_configs[wlan_interface['if_name']]
            self.ovsdb_insert("Wifi_Radio_Config", wlan_interface)

        print("enabling WLANs")
        for uuid in wlan_enabled:
            self.ovsdb_update("Wifi_VIF_Config", [["_uuid", "==", ["uuid",uuid]]], {"enabled":True})

        self.ovsdb_update("AWLAN_Node", [["upgrade_status", "==", 0]], {"upgrade_status":1})

        print("checking AP regestered in postgresql db")
        for network in config['wifi_networks']:
            result = self.ovsdb_select("Wifi_Inet_State",
                [["if_name", "==", network["if_name"]]])['result'][0]['rows']
            while result == []:
                time.sleep(0.5)
                result = self.ovsdb_select("Wifi_Inet_State",
                    [["if_name", "==", network["if_name"]]])['result'][0]['rows']
            print(result)
            ap_user_name = result[0]['hwaddr'].upper().replace(':', '-') + ":" + network['ssid']
            radius_server.add_login_db(ap_user_name, default_password, self.sql_conn)
