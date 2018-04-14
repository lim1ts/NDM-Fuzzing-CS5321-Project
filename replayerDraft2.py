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
    sock.connect((dip, int(dp)))
    sock.bind('',,sp)
    print ("[DEBUG] Socket created and connected")
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
   
    for traffic in traffic_list:
        Dest = traffic[0].split(",")
        DIP = Dest[0].split(":")[0]
        DPort = Dest[0].split(":")[1]
        SPort = Dest[0].split(",")[2]

        conn = new_socket_connection(DIP, DPort, Sport)
        for item in traffic:
            if item == RESPONSE_FROM_SERVER:
                # todo: settle extra ack from handshake
                wait_receive(conn)
            else:
                print ("[DEBUG] SENDING PAYLOAD" + item)
                conn.sendall(item)
                print ("[DEBUG] Payload sent!")

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./replayerDraft2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        replay_PCAP(pcapfile)

if __name__ == '__main__':
    main()
