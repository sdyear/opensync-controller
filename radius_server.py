""" this module opperates as a RADIUS server to authenticate devices connecting to the network """
import struct
import hashlib
import random
import psycopg2
from pyrad import packet, server, dictionary
import six

def build_tunnel_password(secret, authenticator, password):
    """ encrypts tunnel password using the method outlined in rfc2868 """
    #generates a 2 octet byte object with 1 as first bit
    salt = bytes([random.randint(128,255), random.randint(0,255)])
    if isinstance(password, six.text_type):
        password = password.encode('utf-8')

    buf = struct.pack('B', len(password)) + password
    if len(buf) % 16 != 0:
        buf += six.b('\x00') * (16 - (len(buf) % 16))
    result = six.b('')
    hashed = hashlib.md5(secret + authenticator + salt).digest()
    while buf:
        for i in range(16):
            result += bytes((hashed[i] ^ buf[i],))
        last = result[-16:]
        buf = buf[16:]
        hashed = hashlib.md5(secret + last).digest()

    return b'\x00' + salt + result

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
        cur.execute("INSERT INTO radcheck VALUES\
            (" + new_id + ", '" + user_name + "', 'Cleartext-Password', ':=', '" + user_name +"')")
        cur.execute("INSERT INTO radreply VALUES\
            (" + new_id + ", '" + user_name + "', 'Tunnel-Password', ':=', '" + password +"')")
        print("device added to db with User-Name = ", user_name, " and password = ", password)
        sql_conn.commit()
    else:
        print("device with User-Name = ", user_name, " already in db")
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
        print("Received an authentication request from ", pkt['User-Name'])
        #checks if connecting device is in the db
        cur = self.sql_conn.cursor()
        cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck\
            WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
        result = cur.fetchone()
        #if it's in the db and the password is correct
        if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
            #get the tunnel-password for that device
            cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply\
                WHERE Username = '" + pkt['User-Name'][0] + "' ORDER BY id")
            #reply with the tunnel password as an attribute
            reply = self.CreateReplyPacket(pkt)
            cleartext_tunnel_password = cur.fetchone()[3]
            data = build_tunnel_password(reply.secret, pkt.authenticator, cleartext_tunnel_password)
            reply.AddAttribute("Tunnel-Password", data)
            reply.code = packet.AccessAccept
            reply.add_message_authenticator()
            self.SendReplyPacket(pkt.fd, reply)
            print("the device is known, Access-Accept send with Tunnel-Password = ",
                cleartext_tunnel_password)
        #the device isn't in the db
        else:
            print("the device is unknown")
            #look up the AP the device connected to in the db
            print("SELECT id, UserName, Attribute, Value, Op FROM radcheck\
                WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
            cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck\
                WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
            result = cur.fetchone()
            #if the ap is in the db
            if result is not None and result[3]==pkt['Called-Station-Id'][0]:
                print("the AP is known")
                #get the tunnel-password for that ap
                cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply\
                    WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
                #add the device to the db
                add_login_db(str(pkt[1][0],'utf-8'), cur.fetchone()[3], self.sql_conn)
                #look for the device in the db again
                cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck\
                    WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
                result = cur.fetchone()
                #if the device is now in the db
                if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
                    print("the deive is now known")
                    #get the tunnel password for the device
                    cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply\
                        WHERE Username = '" + pkt['User-Name'][0] + "' ORDER BY id")
                    #send a radius reply with the tunnel password as an attribute
                    reply = self.CreateReplyPacket(pkt)
                    data = build_tunnel_password(reply.secret, pkt.authenticator, cur.fetchone()[3])
                    reply.AddAttribute("Tunnel-Password", data)
                    reply.code = packet.AccessAccept
                    reply.add_message_authenticator()
                    self.SendReplyPacket(pkt.fd, reply)
                else:
                    print("adding device ", pkt['User-Name'][0]," failed")
            else:
                print('the AP ', pkt['Called-Station-Id'][0],'is unknown')
