# NDM-Fuzzing-CS5321-Project

## Parse.py 
### Usage
` ./parse.py <pcap.file>
Takes in a single `PCAP` file.
Prints out strings of commands that can be used to replay the dialogs.

` ./replayerDraft.py
Replays a pcap file

## redirectDiffPort.pcap 301.pcap
One of the example pcap files that is used to test the replayability of dialogs.

## test.py
Used to replay the dialog in 301.pcap using sockets. Sockets will handle the SYN, SYN ACK and ACK. The seq num and ack num will be handled as well. After receiving the response, the sockets will then send fin to close the connection. Hence, there is a need to reopen connections after each send. 
Input: - (the ip address and port number are hardcoded inside)
Output: - (this code replays the dialog in 301.pcap and doesn't output anything)
