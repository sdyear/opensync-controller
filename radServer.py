#!/usr/bin/python3
from pyrad import dictionary, packet, server, client
import pdb
import socket
import psycopg2
import struct
import hashlib

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

class FakeServer(server.Server):

    def HandleAuthPacket(self, pkt):
        print("Received an authentication request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))
        #connect to postgresql database
        conn = psycopg2.connect(host='163.7.137.203',dbname='radius', user='radius', password='password')
        #checks if connecting device is in the db
        cur = conn.cursor()
        cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
        result = cur.fetchone()
        #if it's in the db and the password is correct
        if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
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
            #look up the AP the device connected to in the db
            print("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
            cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
            result = cur.fetchone()
            #if the ap is in the db
            if result is not None and result[3]==pkt['Called-Station-Id'][0]:
                #get the tunnel-password for that ap
                cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radreply WHERE Username = '" + pkt['Called-Station-Id'][0] + "' ORDER BY id")
                tunnel_password = cur.fetchone()[3]
                #find the next avaliable id number to use for the device
                cur.execute("SELECT id FROM radcheck ORDER BY id")
                result = cur.fetchall()
                newId = str(result[len(result)-1][0]+2)
                #add the device to the db giving it the tunnel-password for the ap it connected to
                cur.execute("INSERT INTO radcheck VALUES (" + newId + ", '" + str(pkt[1][0],'utf-8') + "', 'Cleartext-Password', ':=', '" + str(pkt[1][0],'utf-8') +"')")
                cur.execute("INSERT INTO radreply VALUES (" + newId + ", '" + str(pkt[1][0],'utf-8') + "', 'Tunnel-Password', ':=', '" + tunnel_password +"')")
                conn.commit()
                #look for the device in the db again
                cur.execute("SELECT id, UserName, Attribute, Value, Op FROM radcheck WHERE Username = '" + pkt['User-Name'][0] +  "' ORDER BY id")
                result = cur.fetchone()
                print(result)
                #if the device is now in the db
                if result is not None and result[3]==pkt.PwDecrypt(pkt['User-Password'][0]):
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

if __name__ == '__main__':

    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("dictionary"),  authport=1812)

    # add clients (address, secret, name)
    '''
    srv.hosts["163.7.137.203"] = server.RemoteHost("163.7.137.203", b"secret", "ap10")
    srv.hosts["127.0.0.1"] = server.RemoteHost("127.0.0.1", b"secret", "localhost")
    srv.hosts["114.134.11.156"] = server.RemoteHost("114.134.11.156", b"secret", "ap1", authport=1811)
    srv.hosts["163.7.137.203"] = server.RemoteHost("163.7.137.203", b"secret", "ap11", authport=1811)
    '''
    srv.hosts["0.0.0.0"] = server.RemoteHost("0.0.0.0", b"secret", "ap10")
    srv.BindToAddress("0.0.0.0")

    # start server
    srv.Run()