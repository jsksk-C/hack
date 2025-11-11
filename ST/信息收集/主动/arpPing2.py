import nmap
target="172.20.186.1-100"
nm = nmap.PortScanner() #创建Nmap扫描器实例这个对象封装了nmap的功能，提供Pythonic的接口可以执行各种nmap扫描并解析结果
nm.scan(target, arguments='-sn -PR')
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())


"""scan方法参数：
target：扫描目标，可以是IP、IP范围、主机名等
arguments：nmap命令行参数
参数详解：
-sn参数：

也称为-sP（ping扫描）功能：只进行主机发现，不进行端口扫描行为：跳过端口扫描阶段，只确定主机是否在线
等价于：--disable-port-scan

-PR参数：功能：使用ARP请求进行主机发现适用场景：局域网内的主机发现
工作原理：发送ARP请求包，根据ARP响应判断主机存活优势：在局域网内速度最快，最准确

组合效果：
-sn -PR = 使用ARP协议进行主机发现扫描，不扫描端口"""


"""nm.all_hosts()：返回所有被发现的主机列表（IP地址）     按扫描结果中发现的顺序返回
主机信息访问：
nm[host]：访问特定主机的扫描结果
nm[host].hostname()：获取主机名

通过DNS反向解析获得
如果解析失败，可能返回空字符串或IP本身
nm[host].state()：获取主机状态
返回'up'或'down'
基于主机发现结果
"""