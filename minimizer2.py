#!/usr/env/python
import sys
import subprocess
import time, threading
from scapy.all import *
from subprocess import PIPE
# Custom modules
import replayerDraft2
import parse

# Change this!
CAPTURE_INTERFACE = "lo"

# Takes in action list, replays it
# @returns: boolean result of whether goal is reached.
def test_replay(commandList):
    return replayerDraft2.replay_list(commandList)
    
def ddmin_level2(command_list):
    # At level 2, we know that certain connections have to be made
    # we want to find out if any of the messages sent dont have to be made
    granularity_n = 2
    while True:
        deep_subset = deeper_split(command_list, granularity_n)
        print "[Minimizer Debug] Subsets are: "
        print deep_subset
        test_candidate = []
        subset_len = sys.maxint

        for index, conn_subsets in enumerate(deep_subset):
            full_connection_messages = command_list[index]
            connection_info = full_connection_messages[0]
            print "Index:", index
            current_conn_possible = []
            for each_subset in conn_subsets:
                complement = [c for c in conn_subsets if c is not each_subset]
                flat_complement = [i for sublist in complement for i in sublist]
                flat_complement.insert(0, connection_info)
                #print "COMPLEMENT"
                #print flat_complement
                current_conn_possible.append(flat_complement)
                subset_len = min(subset_len, len(flat_complement) - 1)
            num_subsets = len(current_conn_possible)
            test_candidate.append(current_conn_possible)

        index = 0
        goal_reaching = 0
        while index < num_subsets:
            possible_replay = [item[index] for item in test_candidate]
            print "Possible Replay"
            time.sleep(2)
            if test_replay(possible_replay):
                goal_reaching = 1
                print "[Minimizer Debug] New passing configuration found!"
                command_list = list(possible_replay)
                granularity_n = max(granularity_n-1,2)
                print command_list
                break
            else:
                index += 1

        print "Granularity: %d" % granularity_n
        print "subset_len : %d" % subset_len
        if goal_reaching and granularity_n == subset_len:
                break
        elif not goal_reaching and granularity_n == subset_len:
            print "[Minimizer Debug] Maximum granularity reached. Ending..." 
        else:
            granularity_n = min(granularity_n*2, subset_len)
            print "[Minimizer Debug] Increasing granularity to %d" % granularity_n

        if subset_len == 1:
            pass
    print "Finished Level 2 minimization"
    return command_list

   
# Take in action list from parser.
# Partitions the commandlist into different connections
# and replays it, checking if it reaches the goal.
def ddmin_level1(command_list):
    current_list_passing = test_replay(command_list)
    if current_list_passing:
        # this commandlist reaches the goal
        command_len = len(command_list)
        if command_len == 1:
            return command_list
        else:
            granularity_n = 2
            while command_len >= 2:
                print command_len
                subsets = splitTestSet(command_list, granularity_n)
                print "[Minimizer Debug] Subsets are:"
                for each_set in subsets:
                    complement = [c for c in command_list if c not in each_set]
		    complement_reaching = 0
                    if test_replay(complement):
                        print "[Minimizer Debug] New goal-reaching configuration"
                        print "New list: ", complement
                        granularity_n = max(granularity_n-1, 2)
                        print "[Minimizer Debug] Granularity:%d" % granularity_n
                        complement_reaching = 1
                        commandList = complement
                        command_len = len(command_list)
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
            return command_list
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

def deeper_split(command_list, granularity_n):
    subset_commands = list(command_list)
    # Make subsets of each connection
    for index, each_connection in enumerate(command_list):
        print index
        subset_commands[index] = splitTestSet(each_connection[1:], granularity_n)
    return subset_commands
    
def traffic_sniff(e):
    print "Starting sniffer..."
    traffic= sniff(iface=CAPTURE_INTERFACE, stop_filter=lambda p: e.is_set())
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
    if minimized_connections:
        minimized_connections_level2 = ddmin_level2(minimized_connections)
        print "Final configuration found. Starting capture thread to write .pcap"
        capture_replay(minimized_connections_level2)
        print "Capture complete!"
    else:
        print "Unable to minimize. Quitting!"

def main():
    if len(sys.argv) != 2:
        print ("Usage: ./minimizer2.py <pcap.file>")
    else:
        pcapfile = sys.argv[1]
        minimize(pcapfile)
    
if __name__ == "__main__":
    main()
