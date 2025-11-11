import socket

# 进行 IP 查询
ip = socket.gethostbyname('www.baidu.com')
print(ip)


print('\n')
# 进行 Whois 查询

from whois import whois
data = whois('www.baidu.com')
print(data)
