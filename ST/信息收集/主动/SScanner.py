import requests
import random
import time
import sys
import urllib3
from urllib.parse import urljoin, urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 颜色代码类
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class AdvancedDirectoryScanner:
    def __init__(self, target_url, dict_file=None, threads=10, delay=0, timeout=10, user_agent=None, use_proxy=False):
        self.target_url = target_url.rstrip('/')
        self.dict_file = dict_file or "enhanced_dict.txt"
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.use_proxy = use_proxy
        self.found_paths = []
        self.session = requests.Session()
        self.total_requests = 0
        
        # 用户代理池
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/116.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/115.0.1901.200 Safari/537.36"
        ]
        
        # 代理池（可选）
        self.proxies = [
            {"http": "http://proxy1:8080", "https": "https://proxy1:8080"},
            {"http": "http://proxy2:8080", "https": "https://proxy2:8080"},
        ] if use_proxy else []
        
        # 创建增强字典（如果不存在）
        if not os.path.exists(self.dict_file):
            self.create_enhanced_dictionary()
    
    def create_enhanced_dictionary(self):
        """创建增强版敏感路径字典"""
        sensitive_paths = [
            "# 管理后台路径",
            "admin", "administrator", "login", "manager", "admin/login", "admin.php",
            "wp-admin", "wp-login.php", "administrator/index.php", "user/login",
            "backend", "console", "dashboard", "control", "cp", "cpanel", "webadmin",
            
            "# 数据库管理",
            "phpmyadmin", "pma", "myadmin", "mysql", "db", "database", 
            "adminer", "dbadmin", "sql", "webdb", "db/db-admin.php",
            "mongodb", "redis", "memadmin",
            
            "# 配置文件泄露",
            "config", "configuration", "config.php", "config.php.bak", "config.php.save",
            "config.json", "config.json.bak", ".env", "env", "settings.py", "config.xml",
            "web.config", "application.ini", "config.inc.php", "database.php",
            "app/config/database.php", "config/database.php", ".config",
            
            "# 备份文件泄露",
            "backup", "backups", "bak", "old", "temp", "tmp", "archive",
            "database.sql", "backup.sql", "www.zip", "site.tar.gz", "backup.zip",
            "backup.tar", "dump.sql", "backup.rar", "backup.7z", "backup.tar.gz",
            "www.tar.gz", "site.bak", "database.bak", "backup/database.sql",
            
            "# 版本控制泄露",
            ".git", ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index",
            ".svn", ".svn/entries", ".svn/wc.db", ".svn/format",
            ".hg", ".hg/store/00manifest.i", ".hg/dirstate",
            ".bzr", ".bzr/branch-format", "CVS", "CVS/Root",
            
            "# 日志文件泄露",
            "logs", "log", "error.log", "access.log", "debug.log", "error_log",
            "apache.log", "nginx.log", "logs/error.log", "logs/access.log",
            
            "# 信息泄露文件",
            "phpinfo.php", "info.php", "test.php", "debug.php", "phpinfo",
            "server-status", "server-info", ".DS_Store", "thumbs.db",
            
            "# API和文档泄露",
            "api", "api/v1", "api/v2", "rest", "graphql", "swagger", "swagger-ui",
            "api-docs", "doc", "docs", "documentation", "help", "readme",
            
            "# 敏感目录",
            ".htaccess", "robots.txt", "crossdomain.xml", "sitemap.xml",
            "package.json", "composer.json", "composer.lock", "yarn.lock",
            "Gemfile", "Gemfile.lock", "requirements.txt",
            
            "# 上传目录",
            "upload", "uploads", "files", "images", "attachments", "media",
            "static", "assets", "resources",
            
            "# 安装和设置文件",
            "install", "setup", "install.php", "setup.php", "upgrade.php",
            "install/index.php", "setup/index.php",
            
            "# 框架特定路径",
            "laravel/.env", "symfony/app/config/parameters.yml",
            "wordpress/wp-config.php", "drupal/sites/default/settings.php",
            "joomla/configuration.php",
            
            "# 其他敏感路径",
            "cgi-bin", "web-inf", "WEB-INF", "META-INF", "includes", "templates",
            "themes", "plugins", "modules", "vendor", "lib", "src", "bin",
            "shell", "cmd", "exec", "system", "passwd", "shadow", ".bash_history"
        ]
        
        try:
            with open(self.dict_file, "w", encoding="utf-8") as f:
                for path in sensitive_paths:
                    f.write(path + "\n")
            print(f"{Colors.GREEN}[+] 已创建增强字典文件: {self.dict_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] 创建字典文件失败: {e}{Colors.END}")
    
    def get_random_headers(self):
        """获取随机请求头"""
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        # 随机添加一些头部以增加迷惑性
        if random.random() > 0.5:
            headers["Referer"] = "https://www.google.com/"
        if random.random() > 0.7:
            headers["DNT"] = "1"
            
        return headers
    
    def get_proxy(self):
        """获取随机代理"""
        if self.proxies and self.use_proxy:
            return random.choice(self.proxies)
        return None
    
    def scan_path(self, path):
        """扫描单个路径"""
        try:
            # 随机延迟
            if self.delay > 0:
                time.sleep(random.uniform(0, self.delay))
            
            # 构建完整URL
            full_url = urljoin(self.target_url, path)
            
            # 获取随机请求头和代理
            headers = self.get_random_headers()
            proxy = self.get_proxy()
            
            # 发送请求
            response = self.session.get(
                full_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                proxies=proxy
            )
            
            self.total_requests += 1
            
            # 检查响应状态
            status = response.status_code
            content_length = len(response.content)
            
            # 敏感状态码
            sensitive_status = [200, 301, 302, 403, 401, 500]
            
            if status in sensitive_status and content_length > 100:
                # 检查响应内容中的敏感信息
                sensitive_keywords = self.check_sensitive_info(response.text)
                
                result = {
                    'url': full_url,
                    'status': status,
                    'size': content_length,
                    'sensitive_info': sensitive_keywords
                }
                
                return result
                
        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            pass
            
        return None
    
    def check_sensitive_info(self, content):
        """检查响应内容中的敏感信息"""
        sensitive_patterns = {
            'password': ['password', 'pwd', 'passwd', '密码'],
            'key': ['api_key', 'secret_key', 'private_key', '密钥'],
            'token': ['token', 'access_token', 'refresh_token'],
            'database': ['database', 'db_host', 'db_user', 'db_pass'],
            'config': ['config', 'configuration', 'setting'],
            'email': ['email', 'mail', 'smtp'],
            'admin': ['admin', 'administrator', '管理员']
        }
        
        found_keywords = []
        content_lower = content.lower()
        
        for category, keywords in sensitive_patterns.items():
            for keyword in keywords:
                if keyword in content_lower:
                    found_keywords.append(keyword)
                    break  # 每个类别只记录一次
        
        return found_keywords
    
    def print_result(self, result):
        """彩色打印扫描结果"""
        status = result['status']
        url = result['url']
        size = result['size']
        sensitive_info = result['sensitive_info']
        
        # 根据状态码设置颜色
        if status == 200:
            status_color = Colors.GREEN
        elif status in [301, 302]:
            status_color = Colors.BLUE
        elif status == 403:
            status_color = Colors.YELLOW
        elif status == 401:
            status_color = Colors.MAGENTA
        else:
            status_color = Colors.RED
        
        # 构建输出字符串
        output = f"{status_color}[{status}]{Colors.END} {Colors.BOLD}{url}{Colors.END} (大小: {size} bytes)"
        
        # 如果有敏感信息，用红色标出
        if sensitive_info:
            output += f" {Colors.RED}[敏感信息: {', '.join(sensitive_info)}]{Colors.END}"
        
        print(output)
    
    def load_dictionary(self):
        """加载字典文件"""
        paths = []
        try:
            with open(self.dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        paths.append(line)
            return paths
        except FileNotFoundError:
            print(f"{Colors.RED}[-] 字典文件不存在: {self.dict_file}{Colors.END}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[-] 读取字典文件失败: {e}{Colors.END}")
            return []
    
    def run_scan(self):
        """运行扫描"""
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}             高级敏感目录和信息扫描工具{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        
        # 加载字典
        print(f"{Colors.YELLOW}[*] 正在加载字典文件...{Colors.END}")
        paths = self.load_dictionary()
        if not paths:
            return
        
        print(f"{Colors.GREEN}[+] 成功加载 {len(paths)} 个测试路径{Colors.END}")
        print(f"{Colors.YELLOW}[*] 开始扫描目标: {self.target_url}{Colors.END}")
        print(f"{Colors.YELLOW}[*] 线程数: {self.threads}, 延迟: {self.delay}秒{Colors.END}")
        print(f"{Colors.CYAN}{'-'*80}{Colors.END}")
        
        start_time = time.time()
        
        # 使用线程池进行并发扫描
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有任务
            future_to_path = {executor.submit(self.scan_path, path): path for path in paths}
            
            # 处理完成的任务
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    self.found_paths.append(result)
                    self.print_result(result)
        
        # 扫描完成统计
        end_time = time.time()
        scan_time = end_time - start_time
        
        print(f"{Colors.CYAN}{'-'*80}{Colors.END}")
        print(f"{Colors.BOLD}扫描完成!{Colors.END}")
        print(f"{Colors.GREEN}[+] 总共测试: {len(paths)} 个路径{Colors.END}")
        print(f"{Colors.GREEN}[+] 发现有效: {len(self.found_paths)} 个路径{Colors.END}")
        print(f"{Colors.GREEN}[+] 总请求数: {self.total_requests}{Colors.END}")
        print(f"{Colors.GREEN}[+] 扫描耗时: {scan_time:.2f} 秒{Colors.END}")
        print(f"{Colors.GREEN}[+] 平均速度: {self.total_requests/scan_time:.2f} 请求/秒{Colors.END}")
        
        # 保存结果到文件
        self.save_results()
    
    def save_results(self):
        """保存扫描结果到文件"""
        if not self.found_paths:
            return
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.txt"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"扫描目标: {self.target_url}\n")
                f.write(f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"发现路径: {len(self.found_paths)} 个\n\n")
                
                for result in self.found_paths:
                    sensitive_info = ", ".join(result['sensitive_info']) if result['sensitive_info'] else "无"
                    f.write(f"[{result['status']}] {result['url']} (大小: {result['size']} bytes, 敏感信息: {sensitive_info})\n")
            
            print(f"{Colors.GREEN}[+] 扫描结果已保存到: {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] 保存结果失败: {e}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="高级敏感目录和信息扫描工具")
    parser.add_argument("target", help="目标URL")
    parser.add_argument("-d", "--dict", help="字典文件路径", default="enhanced_dict.txt")
    parser.add_argument("-t", "--threads", type=int, help="线程数", default=10)
    parser.add_argument("--delay", type=float, help="请求延迟(秒)", default=0)
    parser.add_argument("--timeout", type=int, help="请求超时(秒)", default=10)
    parser.add_argument("--proxy", action="store_true", help="使用代理")
    
    args = parser.parse_args()
    
    # 创建扫描器实例
    scanner = AdvancedDirectoryScanner(
        target_url=args.target,
        dict_file=args.dict,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        use_proxy=args.proxy
    )
    
    # 运行扫描
    scanner.run_scan()

if __name__ == "__main__":
    # 如果没有参数，显示使用说明
    if len(sys.argv) == 1:
        print(f"{Colors.CYAN}{Colors.BOLD}高级敏感目录和信息扫描工具{Colors.END}")
        print(f"使用方法: python {sys.argv[0]} <目标URL> [选项]")
        print("\n选项:")
        print("  -d, --dict FILE    指定字典文件")
        print("  -t, --threads NUM  线程数 (默认: 10)")
        print("  --delay SECONDS    请求延迟(秒)")
        print("  --timeout SECONDS  请求超时(秒)")
        print("  --proxy            使用代理")
        print(f"\n示例:")
        print(f"  python {sys.argv[0]} http://example.com")
        print(f"  python {sys.argv[0]} http://testphp.vulnweb.com -t 20 --delay 0.5")
        print(f"  python {sys.argv[0]} https://target.com -d custom_dict.txt --proxy")
        sys.exit(1)
    
    main()