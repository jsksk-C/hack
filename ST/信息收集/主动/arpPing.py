"""scapy.all：Scapy的主要模块，提供所有网络数据包操作功能
srp：发送接收函数，工作在第二层（数据链路层）
Ether：以太网帧类，用于构建数据链路层帧
ARP：ARP协议类，用于构建ARP数据包"""
from scapy.all import srp,Ether,ARP
dst="172.20.186.84"

#Ether(dst="ff:ff:ff:ff:ff:ff")：创建以太网帧  dst="ff:ff:ff:ff:ff:ff"：设置目标MAC为广播地址
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dst),timeout=2)
"""ARP(pdst=dst)：创建ARP请求包
pdst：目标协议地址（IP地址）
ARP包默认是请求类型（op=1）

/操作符：数据包分层组合
将Ethernet帧和ARP包组合成完整的数据包
形成：Ethernet头部 + ARP数据

srp函数：功能：在第二层发送数据包并接收回复
返回值：返回两个列表
ans：包含(发送包, 接收包)元组的列表（有应答的）
unans：未应答的包列表

参数：timeout=2：等待应答的超时时间（秒）
"""
for s,r in ans:
    print("Target is alive")
    print(r.sprintf("%Ether.src% - %ARP.psrc%"))
"""r.sprintf("%Ether.src% - %ARP.psrc%")：格式化输出
%Ether.src%：应答包的源MAC地址
%ARP.psrc%：应答包中的源IP地址
"""
