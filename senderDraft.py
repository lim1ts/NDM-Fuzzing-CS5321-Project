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
resvPack = []

client = '192.168.56.1'
server = '192.168.56.129'

def sendSYN(synPack):
    print 'Sending SYN'
    newSYN = sinOverride(synPack)
    resp = sr1(newSYN)
    sentPack.append(newSYN)
    recvPack.append(resp)
    return resp


def sendACK(srvResP):
    print 'sending ACK'
    if srvResP['TCP'].flags != 16L:
        #send the ack
        ackPack = IP(src = srvResP['IP'].dst, dst = srvResP['IP'].src) / TCP(flags = 16L, seq = srvResP.ack, ack = srvResP.seq+1, dport = srvResP['TCP'].sport, sport = srvResP['TCP'].dport)
        send(ackPack)



def replayPCAP(pcaps):
    for p in pcaps:
        if p['TCP'].flags == 1L:
            sendSYN(p)
        elif p.src == server:
            sendACK(p)
        else:
            p['IP'].src = client
            p['IP'].dst = server
            send(p)
            
    # if pack is a SYN do: sendSYN
    # if its a received packet then do: sendACK
    # if its an ACK then ignore
    
        
        
def sinOverride(packet):
    pack = packet
    pack.seq = randint(0,2**32-1)
    return pack

def main ():
    pcapfile = rdpcap('redirectDiffPort.pcap')
    replayPCAP(pcapfile)

if __name__ == '__main__':
    main()
