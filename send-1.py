#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline
from bitstring import BitArray, BitStream

import time
import threading
from utils.head import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def send_scapy(pkt, num, iface):
    for i in range(0, num):
        sendp(pkt, iface=iface, verbose=False)
    # end = time.time()

def send_s(udpLink, byteContent, addr):
    udpLink.sendto(byteContent, addr)

def send_socket(num, address, port, content, endContent):
    udpLink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (address, port)

    threads = []
    for i in range(0, num):
        thread = threading.Thread(target=send_s, args=(udpLink, content, addr))
        thread.setDaemon(False)
        threads.append(thread)
        thread.start()
        time.sleep(0.0001)
    time.sleep(0.01)
    for t in threads:
        t.join()

    if endContent is not None:
        send_s(udpLink, endContent, addr)
    
def send_socket_congestion(num, address, port, content, endContent):
    udpLink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (address, port)

    threads = []
    it = (num+1000-1)/1000
    for j in range(0, it):
        if (num - 1000*j) >= 1000:
            max_it = 1000
        else:
            max_it = num - 1000*j
        
        for i in range(0, max_it):
            thread = threading.Thread(target=send_s, args=(udpLink, content, addr))
            thread.setDaemon(False)
            threads.append(thread)
            thread.start()
        time.sleep(0.01)

    for t in threads:
        t.join()
    time.sleep(0.01)
    if endContent is not None:
        send_s(udpLink, endContent, addr)

def write_file():
    # loginfo = "send: "+str(int(time.time()*1000*1000*1000)) + "\n"
    loginfo = "send: " + str(int(time.time()*1000*1000*1000)) +" "
    f = open('zzzzz_send_receive_time.txt', 'a')
    f.write(loginfo)
    f.close()


def byteSeries(num, length):
    portOct = int(num)
    portBin = bin(portOct)[2:]
    # print(portBin)
    # length = 8
    portBinPretty = '0' * ((length  - int(len(portBin))) % length) + portBin
    return portBinPretty

bind_layers(UDP, SourceRoute)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, AGG, bos=1)


def pack_packet(addr, iface, s):
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr) /  UDP(dport=4321, sport=0x1234) 
    i = 0
    for p in s:
        try:
            pkt = pkt / SourceRoute(bos=0, port=int(p))
            i = i+1
        except ValueError:
            pass
    if pkt.haslayer(SourceRoute):
        pkt.getlayer(SourceRoute, i).bos = 1

    pkt = pkt / AGG(id = 0, time_flag = 1, num = 2, agglen = 4, ingress_time = 0, egress_time =0, value1 = 1, value2 = 2, value3 = 3, value4 = 5 ) 
    return pkt
def pack_udp_packet(addr, iface, s):
    bin_data = ""
    i = 0
    print(s)
    for p in s:
        # print(p)
        try:
            if i == len(s)-1:
                bin_data = bin_data + byteSeries(1, 7) + byteSeries(int(p), 9)
                break
            else:
                bin_data = bin_data + byteSeries(0, 7) + byteSeries(int(p), 9)
        except ValueError:
            pass
        i = i + 1
        # print(bin_data)

    
    bin_data += byteSeries(1, 8) + byteSeries(1, 8) + byteSeries(1, 32) + byteSeries(1, 32) + byteSeries(1, 48) + byteSeries(1, 48)

    for i in range(1, 246):
        bin_data += byteSeries(i, 32)
    byteContent = BitArray('0b' + bin_data).bytes
    return byteContent

def pack_udp_packet_agg(addr, iface, s, agg_idx):
    bin_data = ""
    i = 0
    print(s)
    for p in s:
        # print(p)
        try:
            if agg_idx == i:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(7, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(6, 7) + byteSeries(int(p), 9)
    
            else:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(1, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(0, 7) + byteSeries(int(p), 9)
        except ValueError:
            pass
        i = i + 1
        # print(bin_data)

    
    bin_data += byteSeries(1, 8) + byteSeries(1, 8) + byteSeries(1, 32) + byteSeries(1, 32) + byteSeries(1, 48) + byteSeries(1, 48)

    for i in range(1, 341):
        bin_data += byteSeries(i, 32)
    byteContent = BitArray('0b' + bin_data).bytes
    return byteContent

def pack_udp_packet_agg_end(addr, iface, s, agg_idx):
    bin_data = ""
    i = 0
    print(s)
    for p in s:
        # print(p)
        try:
            if agg_idx == i:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(7, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(6, 7) + byteSeries(int(p), 9)
    
            else:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(1, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(0, 7) + byteSeries(int(p), 9)
        except ValueError:
            pass
        i = i + 1
        # print(bin_data)

    
    bin_data += byteSeries(199, 8) + byteSeries(1, 8) + byteSeries(1, 32) + byteSeries(1, 32) + byteSeries(1, 48) + byteSeries(1, 48)

    for i in range(1, 341):
        bin_data += byteSeries(i, 32)
    byteContent = BitArray('0b' + bin_data).bytes
    return byteContent


def pack_udp_packet_drop(addr, iface, s, agg_idx):
    bin_data = ""
    i = 0
    print(s)
    for p in s:
        # print(p)
        try:
            if agg_idx == i:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(9, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(8, 7) + byteSeries(int(p), 9)
    
            else:
                if i == len(s)-1:
                    bin_data = bin_data + byteSeries(1, 7) + byteSeries(int(p), 9)
                    break
                else:
                    bin_data = bin_data + byteSeries(0, 7) + byteSeries(int(p), 9)
        except ValueError:
            pass
        i = i + 1
        # print(bin_data)

    bin_data += byteSeries(1, 8) + byteSeries(1, 8) + byteSeries(1, 32) + byteSeries(1, 32) + byteSeries(1, 48) + byteSeries(1, 48)

    for i in range(1, 341):
        bin_data += byteSeries(i, 32)
    byteContent = BitArray('0b' + bin_data).bytes
    return byteContent



"""
bos: 
0: the next is SourceRoute
1: this is the last one absolutly 
 
6: this switch needs aggragation
7: this switch needs aggragation also last hop

8: after aggragation drop 
9: after aggragation drop also last hop

./send.py  21 1 1 30M
argv[0] ./send.py
argv[1] port_lists
argv[2] place of aggegeation 
argv[3] whether forward in this place
argv[4] the amount of data

"""
def main():

    if len(sys.argv)<4:
        print 'pass 4 arguments: <ports>, <agg_idx>, <whether_forward> '
        exit(1)

    # sys.argv[2] 
    # sys.argv[3]

    addr = socket.gethostbyname("10.0.2.2")

    s =  sys.argv[1]
    print('s:', s)

    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))
    

    agg_idx = int(sys.argv[2])
    whether_forward = int(sys.argv[3])

    if agg_idx < 0 or agg_idx >= len(s):
        print "error agg_idx"
        exit(1)
    if whether_forward is not 0 and whether_forward is not 1:
        print "error whether_forward"
        exit(1)

    # pkt = pack_packet(addr, iface, s)
    # pkt.show2()

    # print(byteContent)

    # sendp(pkt, iface=iface, verbose=False)
    # num = int(sys.argv[2])

    num = int(sys.argv[4])
    # num = 1

    print("Packet number: %d "%num)


    # print( byteContent)
    # begin = time.time()

    # send_scapy(pkt, num, iface)
    
    write_file()
    if whether_forward == 1:
        byteContent = pack_udp_packet_agg(addr, iface, s, agg_idx)
        endContent = pack_udp_packet_agg_end(addr, iface, s, agg_idx)
        # send_socket(num, addr, 4321, byteContent, endContent)
        send_socket_congestion(num, addr, 4321, byteContent, endContent)
    else:
        byteContent = pack_udp_packet_drop(addr, iface, s, agg_idx)
        send_socket(num, addr, 4321, byteContent, None)

    # end = time.time()
    # print end-begin

if __name__ == '__main__':
    main()
