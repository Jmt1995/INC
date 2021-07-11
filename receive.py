#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
import time


from utils.head import *

def write_file():
    # loginfo = "send: "+str(int(time.time()*1000*1000*1000)) + "\n"
    loginfo = "rece: "+ str(int(time.time()*1000*1000*1000)) +"\n"
    # f = open('zzzzz_send_receive_time.txt', 'a')
    f = open(sys.argv[1], 'a')
    
    f.write(loginfo)
    f.close()

count = 0
def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def handle_pkt(pkt):
    global count
    # if TCP in pkt and pkt[TCP].dport == 1234:
    # print "got a packet"
    
    count  = count + 1

    if pkt.getlayer(AGG) is not None:
        if pkt.getlayer(AGG).num == 90000:
            write_file()

            pkt.show2()
            # exit(1)
    print count
    # pkt.show2()

    # write_file()
    #    hexdump(pkt)
    sys.stdout.flush()

# bind_layers(UDP, SourceRoute)
# bind_layers(SourceRoute, SourceRoute, bos=0)
# bind_layers(SourceRoute, SourceRoute, bos=6)
# bind_layers(SourceRoute, SourceRoute, bos=8)
# bind_layers(SourceRoute, AGG, bos=9)
# bind_layers(SourceRoute, AGG, bos=7)
# bind_layers(SourceRoute, AGG, bos=1)

bind_layers(UDP, AGG)

# argv[1] filename
def main():
    if len(sys.argv)<2:
        print 'pass 1 arguments: <output_filename> '
        exit(1)
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
