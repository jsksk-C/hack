# 使用nmap 进行多种方式扫描

import nmap

target = "172.20.186.84"
nm = nmap.PortScanner()

# 方式1: ARP扫描（局域网）
print("=== ARP扫描 ===")
nm.scan(target, arguments='-sn -PR')
for host in nm.all_hosts():
    print(f"主机 {host} 状态: {nm[host].state()}")

# 方式2: ICMP扫描
print("\n=== ICMP扫描 ===")  
nm.scan(target, arguments='-sn -PE')
for host in nm.all_hosts():
    print(f"主机 {host} 状态: {nm[host].state()}")

# 方式3: TCP SYN扫描
print("\n=== TCP SYN扫描 ===")
nm.scan(target, arguments='-sn -PS22,80,443')
for host in nm.all_hosts():
    print(f"主机 {host} 状态: {nm[host].state()}")