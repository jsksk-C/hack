#配置Python的logging模块   这是一个更强大和灵活的方法，可以自定义日志输出的格式和目的地：

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
import os

# 创建FTP根目录（如果不存在）
ftp_root = "D:\\ftp_root"  # 修改为你想要的目录
if not os.path.exists(ftp_root):
    os.makedirs(ftp_root)

authorizer = DummyAuthorizer()
# 添加匿名用户访问
authorizer.add_anonymous(ftp_root, perm="elradfmwMT")

handler = FTPHandler
handler.authorizer = authorizer
handler.debug_level = 2  # 设置详细日志

server = FTPServer(('0.0.0.0', 2100), handler)
print(f"FTP服务器启动在 0.0.0.0:2100")
print(f"FTP根目录: {ftp_root}")
print("可以使用匿名登录")
print("按 Ctrl+C 停止服务器")
server.serve_forever()