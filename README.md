# NDM-Fuzzing-CS5321-Project

## Parse.py 
### Usage
` ./parse.py <pcap.file>`
Takes in a single `PCAP` file.
Returns a strings of commands to be interpreted by replayer.py module.
To use this as a module: `import parse`
### Explaination
The traffic is extracted from the file and categorized into different `dialogs`.

Each `Dialog` is defined as the traffic, sent and received, for a unique connection between 2 hosts. 

Flow ID (FID) is defined as:
`{SourceIP:SourcePort, DestinationIP:DestinationPort, Protocol}`.

We store each dialog in a dictionary datastructure, using the FID as key, and the sent/received traffic as the values.

## replayerDraft.py
### Usage
` ./replayerDraft.py`
Draft module to replay a series of traffic.
#### NOT COMPLETE

## replayerDraft2.py
### Usage 
`./ replayerDraft2.py <pcap_file>`
Module (draft) used to replay a series of traffic. Will interpret output from `parse.py`.

Difference from first replayer is that this uses python sockets to make connections. Dependent on `parse.py`, uses it as a import module.


## test.py
Used to replay the dialog in 301.pcap using sockets. Sockets will handle the SYN, SYN ACK and ACK. The seq num and ack num will be handled as well. After receiving the response, the sockets will then send fin to close the connection. Hence, there is a need to reopen connections after each send. 
Input: - (the ip address and port number are hardcoded inside)
Output: - (this code replays the dialog in 301.pcap and doesn't output anything)


### redirectDiffPort.pcap 301.pcap
One of the example pcap files that is used to test the replayability of dialogs.
