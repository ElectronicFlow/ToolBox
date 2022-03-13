import socket
from scapy.all import *
from netaddr import *
#get a target and port and return the banner
def bannergrab(target, port):
	sock = socket.socket()
	sock.settimeout(11)
	sock.connect((target,port))
	# sock.send('GET HTTP/1.1 \r\n')
	ret = sock.recv(1024)
	return str(ret)
#get ports list drom the tcp top file
def get_ports_list(count):
    #init top x tcp ports
    t_ports = []
    with open("tcp.top.csv", 'r') as f:
        for line in f:
            t_ports.append(int(line.split()[1].split('/')[0]))
            if len(t_ports) == count:
                break

    return t_ports

#init
target = '192.168.1.1'
t_ports = get_ports_list(1500)
timeout = 13

pkt = IP(dst = target)/TCP(sport = RandShort(), dport = t_ports)
ans, unans = sr(pkt, timeout = timeout, verbose = 0)
openports=[]
for packet in ans:
		if packet[1].haslayer(TCP):
			if packet[1][TCP].flags == 'SA':
				openports.append(packet[1][TCP].sport)
print(openports)

for port in openports:
	try:
		print('port:',port,bannergrab(target,port))
	except Exception as msg:
		print(msg,':',target,port)
