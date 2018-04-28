#!/usr/env/python
# Scapy
from scapy.all import *
# Python
from random import randint
import time
import socket
# Custom modules
import parse

RESPONSE_FROM_SERVER = parse.RESPONSE_FROM_SERVER
HARDCODED_FILE_GOAL = open("server/var/www/cprogram.zip", "rb")
HARDCODED_GOAL_CONTENTS = HARDCODED_FILE_GOAL.read()

# Creates a new connection using sockets.
# @params destination IP, Port and source port
# @returns the socket made
def new_socket_connection(dip,dp,sp):
    print ("[DEBUG] Attempting to create new connection to " + dip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Comment out the former, and de-comment latter 
    # if you want OS to auto-alloc source port
    #sock.bind(('',int(sp)))
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
    reply = sock.recv(8192)
    time.sleep(1)
    print ("[DEBUG] RESPONSE RECEIVED")
    is_goal= False
    if HARDCODED_GOAL_CONTENTS in reply:
        is_goal = True
        print "[DEBUG] GOAL IS REACHED"
        print is_goal
    print reply 
    return is_goal

# Replays a PCAP file 
# Translates it into commands in the form of Actions Lists and
# creates sockets, wait for replies and sends payloads.
def replay_PCAP(pcaps):
    conn_dict = parse.parse_into_connections(pcaps)
    traffic_list = parse.commands_from_dict_sockets(conn_dict)
    replay_list(traffic_list)

# Replays an action list of commands
# Similarly, creates sockets, wait for replies and sends payloads.
def replay_list(traffic_list):
    is_reaching_goal = False

    for traffic in traffic_list:
        #time.sleep(1)
        if not is_reaching_goal:
            Dest = traffic[0].split(",")
            SPort = traffic[0].split(",")[2]
        
            DIP = Dest[0].split(":")[0]
            DPort = Dest[0].split(":")[1]
        
            conn = new_socket_connection(DIP, DPort, SPort)
            for item in traffic[1:]:
               if item == RESPONSE_FROM_SERVER:
                    # todo: settle extra ack from handshake
                    is_reaching_goal = wait_receive(conn)
               else:
                    print ("[DEBUG] SENDING PAYLOAD" + item)
                    try:
                        conn.send(item)
                        print ("[DEBUG] Payload sent!")
                    except Exception as e:
                        print e
    return is_reaching_goal

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./replayerDraft2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        replay_PCAP(pcapfile)

if __name__ == '__main__':
    main()
