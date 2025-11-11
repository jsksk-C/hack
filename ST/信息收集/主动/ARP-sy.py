from scapy.all import *
from scapy.layers.l2 import ARP, Ether
print(ls(ARP))
print('\n')
print(ls(Ether))
print('\n')
print(ls(IP))
print('\n')
print(ls(ICMP))