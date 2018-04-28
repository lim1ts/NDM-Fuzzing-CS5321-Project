#!/usr/env/python
import sys
import subprocess
import time, threading
from scapy.all import *
from subprocess import PIPE
# Custom modules
import replayerDraft2
import parse

# Takes in action list, replays it
# @returns: boolean result of whether goal is reached.
def test_replay(commandList):
    return replayerDraft2.replay_list(commandList)
    

# Take in action list from parser.
# Partitions the commandlist into different connections
# and replays it, checking if it reaches the goal.
def ddmin_level1(commandList):
    current_list_passing = test_replay(commandList)
    if current_list_passing:
        # this commandlist reaches the goal
        command_len = len(commandList)
        if command_len == 1:
            return True
        else:
            granularity_n = 2
            while command_len >= 2:
                print command_len
                subsets = splitTestSet(commandList, granularity_n)
                print "[Minimizer Debug] Subsets are:"
                for each_set in subsets:
                    #TODO read into pcap?
                    complement = [c for c in commandList if c not in each_set]
		    complement_reaching = 1
                    if test_replay(complement):
                        print "[Minimizer Debug] New goal-reaching configuration"
                        print "New list: ", complement
                        granularity_n = max(granularity_n-1, 2)
                        print "[Minimizer Debug] Granularity:%d" % granularity_n
                        complement_reaching = 1
                        commandList = complement
                        command_len = len(commandList)
                        break
                    
                    if complement_reaching:
                        if granularity_n == command_len:
                            break
                        else:
                            granularity_n = min(granularity_n*2,commandLen)
                            print "[Minimizer Debug] Granularity:%d" %granularity_n

                    if commandLen == 1:
                        # Can not be divided further
                        pass
            print "[Minimizer Debug] Finished level 1 minimization."
            return commandList
    else:
        print "[Minimizer Debug] This command list cannot reach the goal."
    
# Divide test case into granularity parts.
def splitTestSet(commandList,granularity_n):
    subsets = []
    start = 0
    for i in range(granularity_n):
        subset = commandList[start:start + (len(commandList) - start) / \
                                           (granularity_n - i)]
        subsets.append(subset)
        start = start + len(subset)
    assert len(subsets) == granularity_n
    for s in subsets:
        assert len(s) > 0
    return subsets

def traffic_sniff(e):
    print "Starting sniffer..."
    traffic= sniff(iface="vboxnet0", stop_filter=lambda p: e.is_set())
    wrpcap("min_candidate.pcap", traffic)

    print "Stopped sniffing"

def capture_replay(minimized_connections):
    e = threading.Event()
    traffic_sniffer = threading.Thread(target=traffic_sniff, args=(e,))
    traffic_sniffer.start()
    time.sleep(5)
    test_replay(minimized_connections)
    e.set()

    while True:
        traffic_sniffer.join(2)
        if traffic_sniffer.is_alive():
            print "Cleaning up..."
        else:
            break

def convert_pcap_to_action(pcap_file):
    pcap_conn_dict = parse.parse_into_connections(pcap_file)
    actions = parse.commands_from_dict_sockets(pcap_conn_dict)
    return actions

# Open pcap file
# Write minimized result into new pcap_file
def minimize(pcap_file):
    action_list = convert_pcap_to_action(pcap_file)
    # Start to minimize on the first level
    minimized_connections = ddmin_level1(action_list)
    # Minimize on second level
    #TODO

    print "Final configuration found. Launching capture thread to write pcap file"
    #capture_replay(minimized_connections)
    print "Capture complete!"

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./minimizer2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        minimize(pcapfile)
    
if __name__ == "__main__":
    main()
