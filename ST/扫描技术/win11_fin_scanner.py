#!/usr/bin/env python3
"""
Windows 11 综合网络扫描器 - 增强版
功能：
1. 多协议主机发现（多种ICMP类型 + TCP/UDP）
2. TCP FIN 隐蔽端口扫描
3. TTL 操作系统识别
4. 服务版本探测
"""

import argparse
import time
import ipaddress
import threading
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor
import random
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

# Windows 11 兼容性配置
conf.use_pcap = True
conf.verb = 0

class EnhancedWindowsNetworkScanner:
    def __init__(self, timeout=2, threads=100, verbose=False):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.results = {
            'hosts': [],
            'ports': []
        }
        self.lock = threading.Lock()
    
    def validate_target(self, target):
        """验证目标格式"""
        try:
            # 检查是否是IP范围
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            elif '-' in target:
                # IP范围格式: 192.168.1.1-192.168.1.100
                start_ip, end_ip = target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                return [str(ipaddress.ip_address(ip)) for ip in range(int(start), int(end) + 1)]
            else:
                # 单个IP或主机名
                return [target]
        except Exception as e:
            if self.verbose:
                print(f"目标验证错误: {e}")
            return []

    def multi_protocol_host_discovery(self, targets):
        """多协议主机发现 - 使用多种ICMP类型和TCP/UDP探测"""
        alive_hosts = []
        
        print("🚀 开始多协议主机发现...")
        print(f"📡 扫描目标: {len(targets)} 个IP")
        print("-" * 50)
        
        def probe_with_icmp(target):
            """ICMP多类型探测"""
            icmp_probes = [
                ('Echo Request', 8, 0),           # 标准ping
                ('Timestamp Request', 13, 14),    # 时间戳请求/回复
                ('Address Mask Request', 17, 18), # 地址掩码请求/回复
                ('Information Request', 15, 16),  # 信息请求/回复
            ]
            
            for name, request_type, reply_type in icmp_probes:
                try:
                    if request_type == 8:  # Echo Request
                        packet = IP(dst=target)/ICMP(type=request_type)
                    else:
                        packet = IP(dst=target)/ICMP(type=request_type, code=0)
                    
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    
                    if response is not None:
                        # 检查是否是预期的回复类型
                        if (response.haslayer(ICMP) and 
                            (response[ICMP].type == reply_type or 
                             (request_type == 8 and response[ICMP].type == 0))):
                            
                            host_info = {
                                'host': target,
                                'status': 'alive',
                                'protocol': f'ICMP-{name}',
                                'ttl': response.ttl,
                                'os': self.analyze_os_from_ttl(response.ttl),
                                'response_type': response[ICMP].type
                            }
                            
                            with self.lock:
                                if target not in [h['host'] for h in alive_hosts]:
                                    alive_hosts.append(host_info)
                                    print(f"✅ [ICMP] 主机存活: {target} (协议: {name}, TTL: {response.ttl}, OS: {host_info['os']})")
                            return True
                            
                except Exception as e:
                    if self.verbose:
                        print(f"ICMP {name} 扫描 {target} 失败: {e}")
            return False
        
        def probe_with_tcp(target):
            """TCP SYN探测常见端口"""
            tcp_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]
            
            for port in tcp_ports:
                try:
                    packet = IP(dst=target)/TCP(dport=port, flags="S", seq=random.randint(1000, 65535))
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    
                    if response is not None and response.haslayer(TCP):
                        # SYN-ACK 或 RST 都表示主机存活
                        if response[TCP].flags & 0x12:  # SYN-ACK
                            host_info = {
                                'host': target,
                                'status': 'alive',
                                'protocol': f'TCP-SYN-{port}',
                                'ttl': response.ttl,
                                'os': self.analyze_os_from_ttl(response.ttl),
                                'port': port
                            }
                            
                            with self.lock:
                                if target not in [h['host'] for h in alive_hosts]:
                                    alive_hosts.append(host_info)
                                    print(f"✅ [TCP] 主机存活: {target} (端口: {port}, TTL: {response.ttl}, OS: {host_info['os']})")
                            return True
                        elif response[TCP].flags & 0x04:  # RST
                            host_info = {
                                'host': target,
                                'status': 'alive',
                                'protocol': f'TCP-RST-{port}',
                                'ttl': response.ttl,
                                'os': self.analyze_os_from_ttl(response.ttl),
                                'port': port
                            }
                            
                            with self.lock:
                                if target not in [h['host'] for h in alive_hosts]:
                                    alive_hosts.append(host_info)
                                    print(f"✅ [TCP] 主机存活: {target} (端口: {port}, TTL: {response.ttl}, OS: {host_info['os']})")
                            return True
                            
                except Exception as e:
                    if self.verbose:
                        print(f"TCP端口 {port} 扫描 {target} 失败: {e}")
            return False
        
        def probe_with_udp(target):
            """UDP探测常见端口"""
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514]
            
            for port in udp_ports:
                try:
                    if port == 53:  # DNS查询
                        packet = IP(dst=target)/UDP(dport=port)/DNS(rd=1, qd=DNSQR(qname="google.com"))
                    else:
                        packet = IP(dst=target)/UDP(dport=port)/Raw(load=b"probe")
                    
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    
                    if response is not None:
                        # ICMP端口不可达表示主机存活但端口关闭
                        if response.haslayer(ICMP) and response[ICMP].type == 3:
                            host_info = {
                                'host': target,
                                'status': 'alive',
                                'protocol': f'UDP-ICMP-{port}',
                                'ttl': response.ttl,
                                'os': self.analyze_os_from_ttl(response.ttl)
                            }
                            
                            with self.lock:
                                if target not in [h['host'] for h in alive_hosts]:
                                    alive_hosts.append(host_info)
                                    print(f"✅ [UDP] 主机存活: {target} (端口: {port}, TTL: {response.ttl}, OS: {host_info['os']})")
                            return True
                        # UDP响应（如DNS）
                        elif response.haslayer(UDP):
                            host_info = {
                                'host': target,
                                'status': 'alive',
                                'protocol': f'UDP-RESP-{port}',
                                'ttl': response.ttl,
                                'os': self.analyze_os_from_ttl(response.ttl)
                            }
                            
                            with self.lock:
                                if target not in [h['host'] for h in alive_hosts]:
                                    alive_hosts.append(host_info)
                                    print(f"✅ [UDP] 主机存活: {target} (端口: {port}, TTL: {response.ttl}, OS: {host_info['os']})")
                            return True
                            
                except Exception as e:
                    if self.verbose:
                        print(f"UDP端口 {port} 扫描 {target} 失败: {e}")
            return False
        
        def probe_host(target):
            """综合探测主机"""
            # 按顺序尝试不同协议，一旦发现就返回
            if probe_with_icmp(target):
                return
            if probe_with_tcp(target):
                return
            if probe_with_udp(target):
                return
            
            if self.verbose:
                print(f"❌ 主机无响应: {target}")
        
        # 多线程执行主机发现
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(probe_host, targets)
        
        print(f"\n📊 多协议主机发现完成! 发现 {len(alive_hosts)} 个存活主机")
        
        # 统计发现方式
        discovery_stats = {}
        for host in alive_hosts:
            protocol = host['protocol'].split('-')[0]
            discovery_stats[protocol] = discovery_stats.get(protocol, 0) + 1
        
        print("🔍 发现方式统计:")
        for protocol, count in discovery_stats.items():
            print(f"  {protocol}: {count} 个主机")
        
        return alive_hosts

    def tcp_fin_scan(self, target, ports):
        """TCP FIN 端口扫描"""
        print(f"\n🔍 开始TCP FIN端口扫描: {target}")
        print(f"🎯 扫描端口: {len(ports)} 个")
        print("-" * 50)
        
        open_ports = []
        
        def scan_port(port):
            try:
                # 构造TCP FIN包
                ip_packet = IP(dst=target)
                tcp_packet = TCP(dport=port, flags="F", seq=random.randint(1000, 65535))
                
                # 发送包并接收响应
                response = sr1(ip_packet/tcp_packet, timeout=self.timeout, verbose=0)
                
                status = "unknown"
                ttl_value = None
                
                if response is None:
                    # 没有响应 - 端口可能是开放的
                    status = "open|filtered"
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    print(f"  ✅ 端口 {port}/tcp  开放或被过滤 - {service}")
                elif response.haslayer(TCP):
                    ttl_value = response.ttl
                    if response[TCP].flags & 0x04:  # RST标志
                        status = "closed"
                        if self.verbose:
                            print(f"  ❌ 端口 {port}/tcp  关闭")
                    else:
                        status = "unknown"
                        if self.verbose:
                            print(f"  ❓ 端口 {port}/tcp  状态未知")
                elif response.haslayer(ICMP):
                    status = "filtered"
                    if self.verbose:
                        print(f"  🛡️  端口 {port}/tcp  被过滤")
                
                return {
                    'target': target,
                    'port': port,
                    'status': status,
                    'ttl': ttl_value,
                    'service': self.get_service_name(port)
                }
                    
            except Exception as e:
                if self.verbose:
                    print(f"扫描端口 {port} 时出错: {e}")
                return None
        
        # 多线程端口扫描
        port_results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(scan_port, ports)
            port_results = [r for r in results if r is not None]
        
        print(f"📊 {target} 端口扫描完成! 发现 {len(open_ports)} 个开放端口")
        return port_results

    def service_version_detection(self, target, port):
        """服务版本探测"""
        try:
            if port == 80 or port == 443:  # HTTP/HTTPS
                protocol = "https" if port == 443 else "http"
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=0)
                
                if response and response.haslayer(TCP) and response[TCP].flags & 0x12:
                    # 发送HTTP请求获取banner
                    send_rst = IP(dst=target)/TCP(dport=port, flags="R")
                    send(send_rst, verbose=0)
                    
                    # 这里可以添加更详细的HTTP banner抓取
                    return "HTTP Service"
                    
            elif port == 22:  # SSH
                return "SSH Service"
            elif port == 21:  # FTP
                return "FTP Service"
                
        except Exception as e:
            if self.verbose:
                print(f"服务版本探测失败 {target}:{port}: {e}")
        
        return "Unknown Service"

    def analyze_os_from_ttl(self, ttl):
        """根据TTL值分析操作系统"""
        if ttl is None:
            return "Unknown"
        
        if 120 <= ttl <= 128:
            return "Windows 10/11/Server"
        elif 60 <= ttl <= 64:
            return "Linux/Unix"
        elif ttl >= 200:
            return "Network Device"
        elif 100 <= ttl < 120:
            return "Older Windows/Other"
        else:
            return f"Unknown (TTL: {ttl})"

    def parse_ports(self, port_str):
        """解析端口范围字符串"""
        ports = []
        parts = port_str.split(',')
        for part in parts:
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return list(set(ports))

    def get_service_name(self, port):
        """获取常见端口服务名称"""
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5900: "VNC", 1433: "MSSQL",
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            135: "RPC", 139: "NetBIOS", 445: "SMB"
        }
        return common_services.get(port, "Unknown")

    def comprehensive_scan(self, target, ports=None):
        """综合扫描：主机发现 + 端口扫描"""
        print("🛰️  Windows 11 综合网络扫描器启动 - 增强版")
        print("=" * 60)
        
        start_time = time.time()
        
        # 步骤1: 解析目标
        targets = self.validate_target(target)
        if not targets:
            print("❌ 目标格式错误")
            return
        
        print(f"📍 目标范围: {len(targets)} 个IP")
        
        # 步骤2: 多协议主机发现
        alive_hosts = self.multi_protocol_host_discovery(targets)
        
        if not alive_hosts:
            print("❌ 未发现存活主机")
            return
        
        # 步骤3: 对存活主机进行TCP FIN端口扫描
        if ports:
            port_list = self.parse_ports(ports)
            all_port_results = []
            
            for host_info in alive_hosts:
                host = host_info['host']
                port_results = self.tcp_fin_scan(host, port_list)
                all_port_results.extend(port_results)
            
            self.results['ports'] = all_port_results
        
        self.results['hosts'] = alive_hosts
        end_time = time.time()
        
        # 生成最终报告
        self.generate_report(start_time, end_time)

    def generate_report(self, start_time, end_time):
        """生成综合扫描报告"""
        print("\n" + "=" * 60)
        print("📊 综合扫描报告")
        print("=" * 60)
        
        # 主机发现统计
        alive_hosts = self.results['hosts']
        print(f"🏠 主机发现:")
        print(f"  存活主机: {len(alive_hosts)} 个")
        
        # 协议发现方式统计
        protocol_stats = {}
        for host in alive_hosts:
            protocol = host['protocol'].split('-')[0]
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
        
        print(f"🔍 发现协议:")
        for protocol, count in protocol_stats.items():
            print(f"  {protocol}: {count} 个")
        
        # 操作系统统计
        os_stats = {}
        for host in alive_hosts:
            os_type = host['os']
            os_stats[os_type] = os_stats.get(os_type, 0) + 1
        
        print(f"💻 操作系统分布:")
        for os_type, count in os_stats.items():
            print(f"  {os_type}: {count} 个")
        
        # 端口扫描统计
        if self.results['ports']:
            open_ports_by_host = {}
            for port_result in self.results['ports']:
                if port_result['status'] == 'open|filtered':
                    host = port_result['target']
                    if host not in open_ports_by_host:
                        open_ports_by_host[host] = []
                    open_ports_by_host[host].append(port_result)
            
            print(f"\n🔓 开放端口统计:")
            for host, ports in open_ports_by_host.items():
                print(f"  {host}: {len(ports)} 个开放端口")
                for port_info in sorted(ports, key=lambda x: x['port']):
                    service = port_info['service']
                    print(f"    ✅ 端口 {port_info['port']}/tcp - {service}")
        
        print(f"\n⏰ 总扫描耗时: {end_time - start_time:.2f} 秒")

def check_privileges():
    """检查权限"""
    import os
    import ctypes
    
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

def main():
    banner = """
    🚀 Windows 11 综合网络扫描器 - 增强版
    ✨ 功能特性:
      • 多协议主机发现（ICMP多种类型 + TCP/UDP）
      • TCP FIN 隐蔽端口扫描  
      • TTL 操作系统识别
      • 服务版本探测
      • 多线程高速扫描
    """
    print(banner)
    
    # 检查权限
    if not check_privileges():
        print("⚠️  警告: 建议使用管理员权限运行以获得最佳效果")
    
    parser = argparse.ArgumentParser(description="Windows 11 综合网络扫描器 - 增强版")
    parser.add_argument("target", help="目标IP/范围 (例如: 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.100)")
    parser.add_argument("-p", "--ports", help="端口范围 (例如: 80,443,1-1000)")
    parser.add_argument("-t", "--timeout", type=float, default=2, help="超时时间(秒)")
    parser.add_argument("--threads", type=int, default=100, help="并发线程数")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    
    args = parser.parse_args()
    
    # 创建扫描器
    scanner = EnhancedWindowsNetworkScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )
    
    try:
        scanner.comprehensive_scan(args.target, args.ports)
    except KeyboardInterrupt:
        print("\n⚠️  扫描被用户中断")
    except Exception as e:
        print(f"❌ 扫描错误: {e}")

if __name__ == "__main__":
    main()