#使用内置的调试级别   通过Python代码启动FTP服务器时，你可以在handler中设置 debug_level 来获取详细日志输出：

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

authorizer = DummyAuthorizer()
# 添加匿名用户并指定FTP根目录（替换为你想要的目录路径）
authorizer.add_anonymous("D:\\tmp", perm="elradfmwMT")  # Windows路径示例
# 或者使用Linux风格路径：authorizer.add_anonymous("/tmp", perm="elradfmwMT")

handler = FTPHandler
handler.authorizer = authorizer
handler.debug_level = 2  # 详细日志

server = FTPServer(('0.0.0.0', 2100), handler)
print("FTP服务器启动在 0.0.0.0:2100")
print("按 Ctrl+C 停止服务器")
server.serve_forever()