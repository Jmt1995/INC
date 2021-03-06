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

class SourceRoute(Packet):
    fields_desc = [ BitField("bos", 0, 7),
                   BitField("port", 0, 9)]
class AGG(Packet):
    fields_desc = [ BitField("id", 0, 8),
                    BitField("time_flag", 0, 8),
                    BitField("num", 0, 32),
                    BitField("agglen", 0, 32),
                    BitField("ingress_time", 0, 48),
                    BitField("egress_time", 0, 48),
                    BitField("value1", 0, 32),
                    BitField("value2", 0, 32),
                    BitField("value3", 0, 32),
                    BitField("value4", 0, 32),
                    BitField("value5", 0, 32),
                    BitField("value6", 0, 32),
                    BitField("value7", 0, 32),
                    BitField("value8", 0, 32),
                    BitField("value9", 0, 32),
                    BitField("value10", 0, 32),
                    BitField("value11", 0, 32),
                    BitField("value12", 0, 32),
                    BitField("value13", 0, 32),
                    BitField("value14", 0, 32),
                    BitField("value15", 0, 32),
                    BitField("value16", 0, 32),
                    BitField("value17", 0, 32),
                    BitField("value18", 0, 32),
                    BitField("value19", 0, 32),
                    BitField("value20", 0, 32),
                    BitField("value21", 0, 32),
                    BitField("value22", 0, 32),
                    BitField("value23", 0, 32),
                    BitField("value24", 0, 32),
                    BitField("value25", 0, 32),
                    BitField("value26", 0, 32),
                    BitField("value27", 0, 32),
                    BitField("value28", 0, 32),
                    BitField("value29", 0, 32),
                    BitField("value30", 0, 32),
                    BitField("value31", 0, 32),
                    BitField("value32", 0, 32),
                    BitField("value33", 0, 32),
                    BitField("value34", 0, 32),
                    BitField("value35", 0, 32),
                    BitField("value36", 0, 32),
                    BitField("value37", 0, 32),
                    BitField("value38", 0, 32),
                    BitField("value39", 0, 32),
                    BitField("value40", 0, 32),
                    BitField("value41", 0, 32),
                    BitField("value42", 0, 32),
                    BitField("value43", 0, 32),
                    BitField("value44", 0, 32),
                    BitField("value45", 0, 32),
                    BitField("value46", 0, 32),
                    BitField("value47", 0, 32),
                    BitField("value48", 0, 32),
                    BitField("value49", 0, 32),
                    BitField("value50", 0, 32),
                    BitField("value51", 0, 32),
                    BitField("value52", 0, 32),
                    BitField("value53", 0, 32),
                    BitField("value54", 0, 32),
                    BitField("value55", 0, 32),
                    BitField("value56", 0, 32),
                    BitField("value57", 0, 32),
                    BitField("value58", 0, 32),
                    BitField("value59", 0, 32),
                    BitField("value60", 0, 32),
                    BitField("value61", 0, 32),
                    BitField("value62", 0, 32),
                    BitField("value63", 0, 32),
                    BitField("value64", 0, 32),
                    BitField("value65", 0, 32),
                    BitField("value66", 0, 32),
                    BitField("value67", 0, 32),
                    BitField("value68", 0, 32),
                    BitField("value69", 0, 32),
                    BitField("value70", 0, 32),
                    BitField("value71", 0, 32),
                    BitField("value72", 0, 32),
                    BitField("value73", 0, 32),
                    BitField("value74", 0, 32),
                    BitField("value75", 0, 32),
                    BitField("value76", 0, 32),
                    BitField("value77", 0, 32),
                    BitField("value78", 0, 32),
                    BitField("value79", 0, 32),
                    BitField("value80", 0, 32),
                    BitField("value81", 0, 32),
                    BitField("value82", 0, 32),
                    BitField("value83", 0, 32),
                    BitField("value84", 0, 32),
                    BitField("value85", 0, 32),
                    BitField("value86", 0, 32),
                    BitField("value87", 0, 32),
                    BitField("value88", 0, 32),
                    BitField("value89", 0, 32),
                    BitField("value90", 0, 32),
                    BitField("value91", 0, 32),
                    BitField("value92", 0, 32),
                    BitField("value93", 0, 32),
                    BitField("value94", 0, 32),
                    BitField("value95", 0, 32),
                    BitField("value96", 0, 32),
                    BitField("value97", 0, 32),
                    BitField("value98", 0, 32),
                    BitField("value99", 0, 32),
                    BitField("value100", 0, 32),
                    BitField("value101", 0, 32),
                    BitField("value102", 0, 32),
                    BitField("value103", 0, 32),
                    BitField("value104", 0, 32),
                    BitField("value105", 0, 32),
                    BitField("value106", 0, 32),
                    BitField("value107", 0, 32),
                    BitField("value108", 0, 32),
                    BitField("value109", 0, 32),
                    BitField("value110", 0, 32),
                    BitField("value111", 0, 32),
                    BitField("value112", 0, 32),
                    BitField("value113", 0, 32),
                    BitField("value114", 0, 32),
                    BitField("value115", 0, 32),
                    BitField("value116", 0, 32),
                    BitField("value117", 0, 32),
                    BitField("value118", 0, 32),
                    BitField("value119", 0, 32),
                    BitField("value120", 0, 32),
                    BitField("value121", 0, 32),
                    BitField("value122", 0, 32),
                    BitField("value123", 0, 32),
                    BitField("value124", 0, 32),
                    BitField("value125", 0, 32),
                    BitField("value126", 0, 32),
                    BitField("value127", 0, 32),
                    BitField("value128", 0, 32),
                    BitField("value129", 0, 32),
                    BitField("value130", 0, 32),
                    BitField("value131", 0, 32),
                    BitField("value132", 0, 32),
                    BitField("value133", 0, 32),
                    BitField("value134", 0, 32),
                    BitField("value135", 0, 32),
                    BitField("value136", 0, 32),
                    BitField("value137", 0, 32),
                    BitField("value138", 0, 32),
                    BitField("value139", 0, 32),
                    BitField("value140", 0, 32),
                    BitField("value141", 0, 32),
                    BitField("value142", 0, 32),
                    BitField("value143", 0, 32),
                    BitField("value144", 0, 32),
                    BitField("value145", 0, 32),
                    BitField("value146", 0, 32),
                    BitField("value147", 0, 32),
                    BitField("value148", 0, 32),
                    BitField("value149", 0, 32),
                    BitField("value150", 0, 32),
                    BitField("value151", 0, 32),
                    BitField("value152", 0, 32),
                    BitField("value153", 0, 32),
                    BitField("value154", 0, 32),
                    BitField("value155", 0, 32),
                    BitField("value156", 0, 32),
                    BitField("value157", 0, 32),
                    BitField("value158", 0, 32),
                    BitField("value159", 0, 32),
                    BitField("value160", 0, 32),
                    BitField("value161", 0, 32),
                    BitField("value162", 0, 32),
                    BitField("value163", 0, 32),
                    BitField("value164", 0, 32),
                    BitField("value165", 0, 32),
                    BitField("value166", 0, 32),
                    BitField("value167", 0, 32),
                    BitField("value168", 0, 32),
                    BitField("value169", 0, 32),
                    BitField("value170", 0, 32),
                    BitField("value171", 0, 32),
                    BitField("value172", 0, 32),
                    BitField("value173", 0, 32),
                    BitField("value174", 0, 32),
                    BitField("value175", 0, 32),
                    BitField("value176", 0, 32),
                    BitField("value177", 0, 32),
                    BitField("value178", 0, 32),
                    BitField("value179", 0, 32),
                    BitField("value180", 0, 32),
                    BitField("value181", 0, 32),
                    BitField("value182", 0, 32),
                    BitField("value183", 0, 32),
                    BitField("value184", 0, 32),
                    BitField("value185", 0, 32),
                    BitField("value186", 0, 32),
                    BitField("value187", 0, 32),
                    BitField("value188", 0, 32),
                    BitField("value189", 0, 32),
                    BitField("value190", 0, 32),
                    BitField("value191", 0, 32),
                    BitField("value192", 0, 32),
                    BitField("value193", 0, 32),
                    BitField("value194", 0, 32),
                    BitField("value195", 0, 32),
                    BitField("value196", 0, 32),
                    BitField("value197", 0, 32),
                    BitField("value198", 0, 32),
                    BitField("value199", 0, 32),
                    BitField("value200", 0, 32),
                    BitField("value201", 0, 32),
                    BitField("value202", 0, 32),
                    BitField("value203", 0, 32),
                    BitField("value204", 0, 32),
                    BitField("value205", 0, 32),
                    BitField("value206", 0, 32),
                    BitField("value207", 0, 32),
                    BitField("value208", 0, 32),
                    BitField("value209", 0, 32),
                    BitField("value210", 0, 32),
                    BitField("value211", 0, 32),
                    BitField("value212", 0, 32),
                    BitField("value213", 0, 32),
                    BitField("value214", 0, 32),
                    BitField("value215", 0, 32),
                    BitField("value216", 0, 32),
                    BitField("value217", 0, 32),
                    BitField("value218", 0, 32),
                    BitField("value219", 0, 32),
                    BitField("value220", 0, 32),
                    BitField("value221", 0, 32),
                    BitField("value222", 0, 32),
                    BitField("value223", 0, 32),
                    BitField("value224", 0, 32),
                    BitField("value225", 0, 32),
                    BitField("value226", 0, 32),
                    BitField("value227", 0, 32),
                    BitField("value228", 0, 32),
                    BitField("value229", 0, 32),
                    BitField("value230", 0, 32),
                    BitField("value231", 0, 32),
                    BitField("value232", 0, 32),
                    BitField("value233", 0, 32),
                    BitField("value234", 0, 32),
                    BitField("value235", 0, 32),
                    BitField("value236", 0, 32),
                    BitField("value237", 0, 32),
                    BitField("value238", 0, 32),
                    BitField("value239", 0, 32),
                    BitField("value240", 0, 32),
                    BitField("value241", 0, 32),
                    BitField("value242", 0, 32),
                    BitField("value243", 0, 32),
                    BitField("value244", 0, 32),
                    BitField("value245", 0, 32),
                    BitField("value246", 0, 32),
                    BitField("value247", 0, 32),
                    BitField("value248", 0, 32),
                    BitField("value249", 0, 32),
                    BitField("value250", 0, 32),
                    BitField("value251", 0, 32),
                    BitField("value252", 0, 32),
                    BitField("value253", 0, 32),
                    BitField("value254", 0, 32),
                    BitField("value255", 0, 32),
                    BitField("value256", 0, 32),
                    BitField("value257", 0, 32),
                    BitField("value258", 0, 32),
                    BitField("value259", 0, 32),
                    BitField("value260", 0, 32),
                    BitField("value261", 0, 32),
                    BitField("value262", 0, 32),
                    BitField("value263", 0, 32),
                    BitField("value264", 0, 32),
                    BitField("value265", 0, 32),
                    BitField("value266", 0, 32),
                    BitField("value267", 0, 32),
                    BitField("value268", 0, 32),
                    BitField("value269", 0, 32),
                    BitField("value270", 0, 32),
                    BitField("value271", 0, 32),
                    BitField("value272", 0, 32),
                    BitField("value273", 0, 32),
                    BitField("value274", 0, 32),
                    BitField("value275", 0, 32),
                    BitField("value276", 0, 32),
                    BitField("value277", 0, 32),
                    BitField("value278", 0, 32),
                    BitField("value279", 0, 32),
                    BitField("value280", 0, 32),
                    BitField("value281", 0, 32),
                    BitField("value282", 0, 32),
                    BitField("value283", 0, 32),
                    BitField("value284", 0, 32),
                    BitField("value285", 0, 32),
                    BitField("value286", 0, 32),
                    BitField("value287", 0, 32),
                    BitField("value288", 0, 32),
                    BitField("value289", 0, 32),
                    BitField("value290", 0, 32),
                    BitField("value291", 0, 32),
                    BitField("value292", 0, 32),
                    BitField("value293", 0, 32),
                    BitField("value294", 0, 32),
                    BitField("value295", 0, 32),
                    BitField("value296", 0, 32),
                    BitField("value297", 0, 32),
                    BitField("value298", 0, 32),
                    BitField("value299", 0, 32),
                    BitField("value300", 0, 32),
                    BitField("value301", 0, 32),
                    BitField("value302", 0, 32),
                    BitField("value303", 0, 32),
                    BitField("value304", 0, 32),
                    BitField("value305", 0, 32),
                    BitField("value306", 0, 32),
                    BitField("value307", 0, 32),
                    BitField("value308", 0, 32),
                    BitField("value309", 0, 32),
                    BitField("value310", 0, 32),
                    BitField("value311", 0, 32),
                    BitField("value312", 0, 32),
                    BitField("value313", 0, 32),
                    BitField("value314", 0, 32),
                    BitField("value315", 0, 32),
                    BitField("value316", 0, 32),
                    BitField("value317", 0, 32),
                    BitField("value318", 0, 32),
                    BitField("value319", 0, 32),
                    BitField("value320", 0, 32),
                    BitField("value321", 0, 32),
                    BitField("value322", 0, 32),
                    BitField("value323", 0, 32),
                    BitField("value324", 0, 32),
                    BitField("value325", 0, 32),
                    BitField("value326", 0, 32),
                    BitField("value327", 0, 32),
                    BitField("value328", 0, 32),
                    BitField("value329", 0, 32),
                    BitField("value330", 0, 32),
                    BitField("value331", 0, 32),
                    BitField("value332", 0, 32),
                    BitField("value333", 0, 32),
                    BitField("value334", 0, 32),
                    BitField("value335", 0, 32),
                    BitField("value336", 0, 32),
                    BitField("value337", 0, 32),
                    BitField("value338", 0, 32),
                    BitField("value339", 0, 32),
                    BitField("value340", 0, 32)]

