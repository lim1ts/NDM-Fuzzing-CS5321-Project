#!/usr/bin/python
import sys
from scapy.all import * 
from random import randint

# TCP flags 
SYN_FLAG = 2l
ACK_FLAG = 16l
FIN_ACK_FLAG = 17l
PSH_ACK_FLAG = 24l

# Dummy text for replayer to wait for response.
RESPONSE_FROM_SERVER = "Wait for server to respond"

# Returns a list representation of a dictionary that is sorted.
def sort_pcap_session(conn_dict):
    # To sort pcap sessions according to timestamp.
    sorted_sessions =  sorted(conn_dict.iteritems(), key=lambda (k,v): (v[0].time,k))
    
    return sorted_sessions

# Generate new FID from a packet.
# @params: packet in Scapy format
# @returns: String of generated ID
def generate_new_ID(packet):
    # Each connection ID consists of
    # Source IP, Port
    # Destination IP, Port
    # Protocol
    SIP = packet['IP'].src
    SP = str(packet['TCP'].sport)

    DIP = packet['IP'].dst
    DP = str(packet['TCP'].dport)

    PROT = str(packet['IP'].proto)

    # new_ID = SIP:SP, DIP:DP, PROT
    new_ID = SIP + ":" + SP
    new_ID += ","
    new_ID += DIP + ":" + DP
    new_ID += ","
    new_ID += PROT
    print ("[DEBUG] ID generated:"+ new_ID)

    return new_ID

# Generate Scapy commands from a packet.
# @params: Packet in Scapy format
# @returns: String of Scapy command to send similar packet.
def generate_command(packet):
    IP_Layer = packet['IP']
    command = "IP(proto={}, dst={})".format(IP_Layer.proto, IP_Layer.dst)
    
    if packet.haslayer("UDP"):
        command +="/UDP(dport = {})".format(packet['UDP'].dport)
    else:
        command +="/TCP(dport={}, flags = {})".format(packet['TCP'].dport,
                                            packet['TCP'].flags)

    if (packet.getlayer(3)):
        payload = "/" + packet.getlayer(3).command()
        command += payload

    print command

def commands_from_dict(conn_dict):
    conn_dict = sort_pcap_session(conn_dict)
    command_list = []
    for ID, messageList in conn_dict:
        print ("**** [New connection] ****")
        print (ID)
        SIP = ID.split(":")[0]
        if messageList[0].haslayer('TCP'):
            print ("-Initiate New TCP handshake-")
        for message in messageList:
            IP_layer = message['IP']
            AP_layer = message.getlayer(2)
            if IP_layer.src == SIP and AP_layer.flags != SYN_FLAG and AP_layer.flags != ACK_FLAG and AP_layer != FIN_ACK_FLAG:
                # Connections that are not ACKs and Handshake
                stringCommand = generate_command(message)

# Parses all packets in a PCAP file into connections, defined
# by their FID. Messages are defined as the packets sent and received
# between each unique hosts, and SYN/FIN packets mark the start and end
# of each connection.
# @params : pcap file
# @returns: A dictionary with FID as key, messages as values.
def parse_into_connections(pcapfile):
    all_packets = rdpcap(pcapfile)

    id_stack = []
    conn_dict = {}


    for packet in all_packets:
        #print ("[DEBUG] Stack size: ", len(id_stack))
        #print (id_stack)
        #print ("[DEBUG] Dictionary Size: ", len(conn_dict))

        p_flag = packet['TCP'].flags
        if p_flag == SYN_FLAG:
            new_ID = generate_new_ID(packet)
            #print ("[DEBUG]Adding ", new_ID)
            id_stack.append(new_ID)

            new_list = list()
            conn_dict[new_ID] = new_list
            new_list.append(packet)

        elif p_flag == FIN_ACK_FLAG:
            top_of_stack = id_stack.pop()
            old_list = conn_dict[top_of_stack]
            old_list.append(packet)

            ack_number = packet['TCP'].seq + 1
            for p in all_packets:
                if p['TCP'].ack == ack_number:
                    old_list.append(p)
                    break
        else:
            if len(id_stack) > 0:
                top_of_stack = id_stack[-1]
                old_list = conn_dict[top_of_stack]
                old_list.append(packet)

    return conn_dict 

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./parse.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        conn = parse_into_connections(pcapfile)
        commands_from_dict(conn)

if __name__=="__main__":
    main()
