from netaddr import *
import socket
import sys
from scapy.all import *
import os
#this function checks if a packet is a valid return from a dns server
def checkdns(pkt):
	reply = pkt[1]
	if reply.haslayer('DNS') and not reply.haslayer('ICMP'):
		return True
	else:
		return False
#this function returns 2 lists of valid and invalid dns ip addresses
def request(listservers):
	ans,unans = sr(IP(dst=listservers[0:500])/UDP(dport=53)/DNS(rd=1,opcode=2,qr=0,rcode=0), timeout=20, retry=0)
	valid=[]
	invalid=[]
	print(len(ans))
	print(len(unans))
	for pkt in ans:
		if checkdns(pkt):
			valid.append(pkt[1][IP].src)
		else:
			invalid.append(pkt[1][IP].src)
		for pkt in unans:
			invalid.append(pkt[0][IP].dst)
	return valid,invalid
#this func sends an any DNS request to the domain and returns the answers
def anyreq(dnsservers):
	#checking which dns servers respond to the status check
	validdns,invaliddns = request(dnsservers)
	domain = b'www.cisco.com'
	print('valid:',len(validdns))
	pkt = IP(dst=validdns)/UDP(dport=53, sport = RandShort())/DNS(qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, ad=1, cd=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=1, qd=DNSQR(qname=domain, qtype=255, qclass=1), an=None, ns=None, ar=DNSRROPT(rdata=[EDNS0TLV(optcode=10, optlen=8, optdata=b'\x12\x34\x56\x78\x90\xab\xcd\xef')], rrname=b'.', type=41, rclass=4096, extrcode=0, version=0, z=0, rdlen=None))
	ans,unans = sr(pkt, timeout=5 ,retry=2)
	return ans
#this list will be the final list of ip addresses
ipv4list=[]
#extract the ip addresses from the file
with open ('dns.txt','r') as file:
	for line in file:
		line = line.replace('\n','')
		line = line.replace(' ','')
		#use th validip func from the package
		if valid_ipv4(line):
			ip = IPAddress(line)
			#make sure the address is a public address
			if ip.is_unicast() and not ip.is_private() and not ip.is_reserved():
				ipv4list.append(line)
#removing addresses that repeat themselves (since its a merge of 3 files)
ipv4list = list(set(ipv4list))
print(len(ipv4list))
#calling the function of determining which ips is a real server
pktlist = anyreq(ipv4list)
#checking which packet from the answers is the largest
maxlen=0
for pkt in pktlist:
	if len(pkt[1]) > maxlen:
		maxlen = len(pkt[1])
		maxpkt = pkt[1]
print(maxpkt.show())
print(maxlen)