#!/usr/env python
from scapy.all import *
from random import randint
# Custom modules
import parse

RESPONSE_FROM_SERVER = parse.RESPONSE_FROM_SERVER


# Creates a new connection using sockets.
# @params destination IP, Port and source port
# @returns the socket made
def new_socket_connection(dip,dp,sp):
    print ("[DEBUG] Attempting to create new connection")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.bind(('',int(sp)))
    # Comment out the above, and de-comment below
    # if you want OS to auto-alloc source port
    sock.bind(('',0))
    try:
        sock.connect((dip, int(dp)))
        print ("[DEBUG] Socket created and connected")
    except Exception as e:
        print e
    return sock

# Accepts a python socket and waits for a receive on this socket.
# @params socket to receive on
# @returns the reply that the socket received
def wait_receive(sock):
    print ("[DEBUG] SERVER RESPONSE WAIT")
    reply = sock.recv(1024)
    print ("[DEBUG] RESPONSE RECEIVED")
    return reply

# Replays a PCAP file [BUGGED, DO NOT USE]
# Translates it into commands in the form of Actions Lists and
# creates sockets, wait for replies and sends payloads.
def replay_PCAP(pcaps):
    conn_dict = parse.parse_into_connections(pcaps)
    traffic_list = parse.commands_from_dict_sockets(conn_dict)
    
    packetlist = []
    for traffic in traffic_list:
        Dest = traffic[0].split(",")
        SPort = traffic[0].split(",")[2]
        
        DIP = Dest[0].split(":")[0]
        DPort = Dest[0].split(":")[1]
        
        #sniff_filters = "((ip src host %s and dst host %s) and (src port %s or dst port %s)) and not ip multicast" % (DIP, DIP, SPort, DPort)
        #conn_sniff = sniff(filter=sniff_filters, count=10)
        conn = new_socket_connection(DIP, DPort, SPort)
        for item in traffic:
            if item == RESPONSE_FROM_SERVER:
                # todo: settle extra ack from handshake
                wait_receive(conn)
            else:
                print ("[DEBUG] SENDING PAYLOAD" + item)
                try:
                    conn.sendall(item)
                    print ("[DEBUG] Payload sent!")
                except Exception as e:
                    print e
                    

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./replayerDraft2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        replay_PCAP(pcapfile)

if __name__ == '__main__':
    main()
