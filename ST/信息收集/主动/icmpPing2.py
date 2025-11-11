import nmap

target = '172.20.186.0/24'
nm = nmap.PortScanner()

nm.scan(target, arguments='-PE -sn')

for host in nm.all_hosts():
    print('='*30)
    print('Host: %s (%s)'%(host,nm[host].hostname()))
    print('State: %s' %nm[host].state())
    