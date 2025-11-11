import nmap
"""nmap -A -T4 172.20.187.9"""
# 最简单的扫描示例
nm = nmap.PortScanner()

# 扫描本地主机的常见端口
target = '127.0.0.1'
ports = '20-100'

print(f"开始扫描 {target} 的端口 {ports}...")

result = nm.scan(target, ports)

print(f"扫描完成！发现 {len(nm.all_hosts())} 个主机")

for host in nm.all_hosts():
    print(f"\n主机: {host}")
    print(f"状态: {nm[host].state()}")
    
    for proto in nm[host].all_protocols():
        print(f"\n{proto.upper()} 协议开放端口:")
        ports = nm[host][proto].keys()
        
        for port in ports:
            port_info = nm[host][proto][port]
            if port_info['state'] == 'open':
                print(f"  端口 {port}: {port_info['name']}")
    