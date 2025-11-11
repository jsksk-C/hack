from scapy.all import sr,IP,ICMP

target = '172.20.186.84'

ans,unans = sr((IP(dst=target)/ICMP()),timeout=2)
for snd,rcv in ans:
    print(rcv.sprintf("%IP.src% is alive"))
