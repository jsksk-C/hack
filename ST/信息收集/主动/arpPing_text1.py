from scapy.all import srp, Ether, ARP

# 扫描IP范围
targets = ["172.20.186." + str(i) for i in range(1, 10)]
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=targets), timeout=2)

for sent, received in ans:
    print(f"Active: {received.psrc} - MAC: {received.hwsrc}")