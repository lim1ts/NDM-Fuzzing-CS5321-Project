#!/usr/env python

from scapy.all import *
from random import randint


# sqNum =  randint(0,2**32-1)
# sportNum = random.randint(1024,65535)

# syn = IP(dst='192.168.56.129') / TCP(sport = sportNum, dport=80, flags='S', seq = sqNum)
# syn_ack = sr1(syn)
# send(IP(dst='192.168.56.129') / TCP(sport=syn.sport, dport=80, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1))
# getStr = 'GET / HTTP/1.1\r\nHost: 192.168.56.129\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nIf-Modified-Since: Sat, 24 Feb 2018 08:36:22 GMT\r\nIf-None-Match: W/"5a912406-264"\r\nCache-Control: max-age=0\r\n\r\n'
# request = IP(dst='192.168.56.129') / TCP(flags = 0x018, sport=syn.sport, dport=80, seq=syn_ack.ack, ack=syn_ack.seq + 1) / Raw(getStr)
# reply = sr1(request)



sentPack = []
recvPack = []

client = '192.168.56.1'
server = '192.168.56.129'

###### TODO: a problem with replaying SYN: the checksum fails although I delete the Ether layer, andIP and TCP checksums


def announce(packet):
    print 'Sending SYN from ' + packet['IP'].src + ':' + str(packet['TCP'].sport) + ' ot ' + packet['IP'].dst + ':' + str(packet['TCP'].dport)

def sendSYN(synPack):
    newSYN = sinOverride(synPack)
    if newSYN['TCP'].sport not in range(0,1024):
        newSYN['TCP'].sport = randint(1025, 65536) #this part must be handled later by the tcp session manager class

    newSYN['IP'].src = client
    newSYN['IP'].dst = server
    
    announce(newSYN)
    resp = sr1(newSYN)

    ### Record in tcp session manager
    return resp


def sendACK(srvResP): ##### TODO: replace with Bot that Acks the received messages and logs in tcp session manager
    print 'sending ACK'
    if srvResP['TCP'].flags != 16L:
        #send the ack
        ackPack = IP(src = srvResP['IP'].dst, dst = srvResP['IP'].src) / TCP(flags = 16L, seq = srvResP.ack, ack = srvResP.seq+1, dport = srvResP['TCP'].sport, sport = srvResP['TCP'].dport)
        announce(ackPack)
        send(ackPack)



def replayPCAP(pcaps):
    for pkt in pcaps:
        if pkt is None:
            continue
        else:
            print 'preparing packet'
            p = pkt['IP'] / pkt['TCP']
            del p.chksum
            del p[TCP].chksum
            
        if p['TCP'].flags == 2L:
            print p.summary(), 'is a SYN packet.'
            sendSYN(p)
            
        elif p['IP'].src == server:
            # TODO: write a class that handles TCP session management that keeps track of the sender port: randomize it if its not a reserved port
            # TODO: write an ackBot that acknowledges received packets and returns seq/ack numbers to the TCP session manager
            # Do nothing... let the ackBot handle it.
            pass
            
        else:
            # check if the packet is not an ACK
            # write a sender that sends the packet if it is not an ACK packet (since ackBot handles that job)
            # the sender should get the seq/ack numbers from the ackbot
            # p['IP'].src = client
            # p['IP'].dst = server
            # send(p)
            pass
        
    # if pack is a SYN do: sendSYN
    # if its a received packet then send Ack using ackBot
    # if its an ACK then ignore
    
# def pktSender(p):
#     packet = p['IP'] / p['TCP']

#     packet['IP'].src = client
#     packet['IP'].dst = server

def testPacket(packet):
    
    print packet.chksum, packet[IP].chksum, packet[TCP].chksum,
    

class SessionMngr():
    ## TODO
    ## Holds source IP address : port num
    ## Holds destination IP address port num
    ## Holds protocol
    ## Holds sent and received packets (headers only)
    ## holds client tcp session seq num
    ## holds server tcp session seq num
    pass

        
def sinOverride(packet):
    pack = packet
    pack.seq = randint(0,2**32-1)
    return pack

def main ():
    pcapfile = rdpcap('redirectDiffPort2.pcap')
    
    # for p in pcapfile:
    #     if p['TCP'].flags == 2L:
    #         print p.show()
            
    replayPCAP(pcapfile[0])


if __name__ == '__main__':
    main()
