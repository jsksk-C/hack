# 获取详细主机信息
import nmap
import json

target = "172.20.186.84"
nm = nmap.PortScanner()

nm.scan(target, arguments='-sn -PR --system-dns')

for host in nm.all_hosts():
    print('='*50)
    host_info = nm[host]
    
    print(f"IP地址: {host}")
    print(f"状态: {host_info.state()}")
    print(f"主机名: {host_info.hostname()}")
    
    # 地址信息
    if 'addresses' in host_info:
        for addr_type, addr in host_info['addresses'].items():
            print(f"{addr_type}地址: {addr}")
    
    # 厂商信息（基于MAC地址）
    if 'vendor' in host_info:
        for mac, vendor in host_info['vendor'].items():
            print(f"MAC {mac} 厂商: {vendor}")
    
    # 主机名列表
    if 'hostnames' in host_info:
        for hostname in host_info['hostnames']:
            print(f"主机名类型 {hostname['type']}: {hostname['name']}")
