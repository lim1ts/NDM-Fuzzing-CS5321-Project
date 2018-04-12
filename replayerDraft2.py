#!/usr/env python
from scapy.all import *
from random import randint
# Custom modules
import parse

def new_socket_connection(dip,dp):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(dip, dp)
    print ("[DEBUG] Socket created and connected")
    return sock

def replay_PCAP(pcaps):
    conn_dict = parse_into_connections(pcapfile)
    traffic_list =
    

def main ():
    if len(sys.argv) != 2:
        print ("Usage: ./replayerDraft2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        replay_PCAP(pcapfile)

if __name__ == '__main__':
    main()
