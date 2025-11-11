# 通过ARP   获取更详细信息

from scapy.all import srp,Ether,ARP
dst="172.20.186.84"

ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dst), timeout=2, verbose=0)

if ans:
    for sent, received in ans:
        print("=" * 50)
        print("Target Status: ONLINE")
        print(f"IP Address: {received.psrc}")
        print(f"MAC Address: {received.hwsrc}")
        print(f"Vendor: {received.hwsrc}")  # 可通过MAC前3字节查厂商
        print(f"Response Time: {received.time - sent.time:.3f}s")
else:
    print("Target is offline or unreachable")
