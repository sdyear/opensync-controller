from pyrad import dictionary, packet, server
import struct
import psycopg2
import hashlib

def build_tunnel_password(secret, authenticator, psk):
    """ encrypts tunnel password using the method outlined in rfc2868 """
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
    ''' finds the next avaliable id number in the device db '''
    cur.execute("SELECT id FROM radcheck ORDER BY id")
    result = cur.fetchall()
    if len(result) == 0:
        return '0'
    if len(result) == 1:
        return str(result[0][0]+1)
    return str(result[len(result)-1][0]+2)

def add_login_db(user_name, password, sql_conn):
    """adds an APs username and password to the postgresql db"""
    cur = sql_conn.cursor()
    cur.execute("SELECT * FROM radcheck WHERE Username = '" + user_name + "'")
    result = cur.fetchone()
    #if the ap is not in the db
    if result is None:
        #find the next avaliable id number to use for the device
        new_id = get_next_id(cur)
        print("INSERT INTO radcheck VALUES (" + new_id + ", '" + user_name + "', 'Cleartext-Password', ':=', '" + user_name +"')")
        cur.execute("INSERT INTO radcheck VALUES (" + new_id + ", '" + user_name + "', 'Cleartext-Password', ':=', '" + user_name +"')")
        print("INSERT INTO radreply VALUES (" + new_id + ", '" + user_name + "', 'Tunnel-Password', ':=', '" + password +"')")
        cur.execute("INSERT INTO radreply VALUES (" + new_id + ", '" + user_name + "', 'Tunnel-Password', ':=', '" + password +"')")
    sql_conn.commit()

class RadiusServer(server.Server):
    '''
    custom Radius server that looks up requests in postgresql and can register new devices in DB
    '''

    def __init__(self, sql_config, radius_dict):
        super().__init__(dict=radius_dict)
        self.sql_conn =  psycopg2.connect(host=sql_config['address'],dbname=sql_config['dbname'],
            user=sql_config['user'], password=sql_config['password'])
        self.hosts["0.0.0.0"] = server.RemoteHost("0.0.0.0", b"secret", "APs")
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
            cleartext_tunnel_password = cur.fetchone()[3]
            data = build_tunnel_password(reply.secret, pkt.authenticator, cleartext_tunnel_password)
            print("Cleartext Tunnel Password: ", cleartext_tunnel_password)
            print("build_tunnel_password(): ", data)
            print("PwCrypt()", reply.PwCrypt(cleartext_tunnel_password))
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
                #add the device to the db
                add_login_db(str(pkt[1][0],'utf-8'), cur.fetchone()[3], self.sql_conn)
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