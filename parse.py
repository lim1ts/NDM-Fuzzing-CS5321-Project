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
def generate_new_ID(packet, IPProto):
    # Each connection ID consists of
    # Source IP, Port
    # Destination IP, Port
    # Protocol
    SIP = packet['IP'].src
    SP = str(packet[IPProto].sport)

    DIP = packet['IP'].dst
    DP = str(packet[IPProto].dport)

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

# Generate commands from a connection dictionary. 
# Deprecated. Supposed to output scapy commands, but NEEDS FIXING.
# DO NOT USE.
def commands_from_dict(conn_dict):
    conn_dict = sort_pcap_session(conn_dict)
    command_list = []
    for ID, messageList in conn_dict:
        Dest = ID.split(",")[1]
        Proto = ID.split(",")[2]
        SIP = ID.split(":")[0]
        for message in messageList:
            IP_layer = message['IP']
            AP_layer = message.getlayer(2)
            if IP_layer.src == SIP and AP_layer.flags != SYN_FLAG and AP_layer.flags != ACK_FLAG and AP_layer != FIN_ACK_FLAG:
                # Connections that are not ACKs and Handshake
                stringCommand = generate_command(message)

# Similar to commands_from_dict, but outputs payloads to be used for replayerDraft2
# @params: Takes in a connection dictionary
# @returns: an Action List, a 2 dimensional list that constitutes of all the
# actions a socket connection should be making: making a connection, waiting for
# replies and sending payloads
def commands_from_dict_sockets(conn_dict):
    conn_dict = sort_pcap_session(conn_dict)
    action_list = []
    for ID, messageList in conn_dict:
        
        Dest = ID.split(",")[1]
        Proto = ID.split(",")[2]
        SIP = ID.split(":")[0]
        SPORT = ID.split(",")[0].split(":")[1]
        
        conn_list = []
        new_con = Dest + "," + Proto + "," + SPORT
        conn_list.append(new_con)
        action_list.append(conn_list)
        ignore_first_ack = False
       
        print ("[PARSE DEBUG] Adding new connection to: " + new_con)
        for message in messageList:
            IP_layer = message['IP']
            if IP_layer.haslayer("TCP"):
        
                if not ignore_first_ack:
                    ignore_first_ack = True

                AP_layer = message.getlayer(2)
                if IP_layer.src == SIP and IP_layer.sport == int(SPORT):
                    if AP_layer.flags == ACK_FLAG:
                        print ("[PARSE DEBUG] ACK")
                        conn_list.append(RESPONSE_FROM_SERVER)
                    elif AP_layer.flags != SYN_FLAG and AP_layer.flags != ACK_FLAG and AP_layer != FIN_ACK_FLAG and message.getlayer(3):
                        # Connections that are not ACKs and Handshake
                        print ("[PARSE DEBUG] Send some payload")
                        data_payload = str(message.getlayer(3)).split("'")[0]
                        conn_list.append(data_payload)
            elif IP_layer.haslayer("UDP"):
                data_payload = str(message.getlayer(3)).split("'")[0]
                conn_list.append(data_payload)

        if ignore_first_ack:
            print ("[PARSE DEBUG] Removing first ACK")
            conn_list.remove(RESPONSE_FROM_SERVER)
    print action_list
    return action_list


# Parses all packets in a PCAP file into connections, defined
# by their FID. Messages are defined as the packets sent and received
# between each unique hosts, and SYN/FIN packets mark the start and end
# of each connection.
# @params : pcap file
# @returns: A dictionary with FID as key, messages as values.
def parse_into_connections(pcapfile):
    all_packets = rdpcap(pcapfile)
    # We need UDP count to represent the timestamp for UDP packets
    # instead of actual unique timestamp from the packets, only
    # because it is easier to read which packets came first.
    UDP_count = 0
    id_stack = []
    conn_dict = {}


    for packet in all_packets:
        #print ("[DEBUG] Stack size: ", len(id_stack))
        #print (id_stack)
        #print ("[DEBUG] Dictionary Size: ", len(conn_dict))
        p_flag = 0
        if packet.haslayer("TCP"):
            p_flag = packet['TCP'].flags

            if p_flag == SYN_FLAG:
                new_ID = generate_new_ID(packet, "TCP")
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

        elif packet.haslayer("UDP"):
            UDP_count += 1
            new_ID = generate_new_ID(packet, "UDP") + str(UDP_count)
            id_stack.append(new_ID)
            new_list = list()
            new_list.append(packet)
            conn_dict[new_ID] = new_list

    return conn_dict 

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./parse.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        conn = parse_into_connections(pcapfile)
        #commands_from_dict(conn)
        commands_from_dict_sockets(conn)

if __name__=="__main__":
    main()
