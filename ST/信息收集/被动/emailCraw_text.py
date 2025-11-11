# 邮件爬取

from wsgiref import headers
import requests
from bs4 import BeautifulSoup
import sys
import getopt
import re
import time

# 添加调试模式
DEBUG = True

# 主函数 ，传入用户输入的参数
def start(argv):
    url = ""
    pages = ""
    if len(sys.argv) < 2:
        print("-h 帮助信息;\n")
        sys.exit()
    
    try:
        banner()
        opts,args = getopt.getopt(argv,"-u:-p:-h")
    except getopt.GetoptError:
        print('Error an argument!')
        sys.exit()
    
    for opt,arg in opts:
        if opt == "-u":
            url = arg
        elif opt == "-p":
            pages = arg
        elif opt == "-h":
            print(usage())
            
    
    launcher(url,pages)

#  转义字符设置字体颜色。  开头:\033[显示方式；前景色；背景色m  结尾部分:\033[0m
def banner():
    print('\033[1;34m 大奖欢迎你 \033[0m\n''\033[1;34m 大奖欢迎你 \033[0m\n''\033[1;34m 大奖欢迎你 \033[0m\n')

# 使用规则
def usage():
    print('-h:help 帮助;')
    print('-u:url 帮助;')
    print('-p:pages 帮助;')
    print('-eg:python -u "www.baidu.com" -p 100'+'\n')
    sys.exit()

# 修复：添加headers函数定义
def get_headers(referer):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': referer,
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    return headers

def launcher(url, pages):
    email_num = []
    key_words = ['email','mail','mailbox','邮件','邮箱','postbox']
    
    if DEBUG:
        print(f"[DEBUG] 目标网站: {url}")
        print(f"[DEBUG] 搜索页数: {pages}")
        print(f"[DEBUG] 关键词: {key_words}")

    for page in range(1,int(pages)+1):
        if DEBUG:
            print(f"\n[DEBUG] 正在搜索第 {page} 页...")
            
        for ker_word in key_words:
            if DEBUG:
                print(f"[DEBUG] 使用关键词: {ker_word}")
                
            try:
                bing_emails = bing_search(url,page,ker_word)
                baidu_emails = baidu_search(url,page,ker_word)
                sum_emails = bing_emails + baidu_emails

                if DEBUG:
                    print(f"[DEBUG] Bing找到邮箱数: {len(bing_emails)}")
                    print(f"[DEBUG] 百度找到邮箱数: {len(baidu_emails)}")

                for email in sum_emails:
                    if email in email_num:
                        pass
                    else:
                        print(f"\033[1;32m找到邮箱: {email}\033[0m")
                        with open('data.txt','a+') as f:
                            f.write(email + '\n')
                        email_num.append(email)
                        
                # 添加延迟避免请求过快
                time.sleep(1)
                
            except Exception as e:
                if DEBUG:
                    print(f"[ERROR] 搜索过程中出错: {e}")
                continue
                
    if DEBUG and len(email_num) == 0:
        print("\n[DEBUG] 没有找到任何邮箱，可能的原因:")
        print("1. 网站没有公开的邮箱地址")
        print("2. 搜索引擎反爬虫机制")
        print("3. 网络连接问题")
        print("4. 解析规则需要调整")

def bing_search(url,page,key_word):
    try:
        referer = "http://cn.bing.com/search?q=email+site%3abaidu.com&qs=n&sp=-1&pq=emailsite%3abaidu.com&first=1&FORM=PERE1"

        conn = requests.session()
        
        bing_url = "http://cn.bing.com/search?q=" + key_word + "+site%3a" + url + "&qs=n&sp=-1&pq=" + key_word + "site%3a" + url + "&first=" + str(
            (page-1)*10) + "&FORM=PERE1"
        
        if DEBUG:
            print(f"[DEBUG] Bing搜索URL: {bing_url}")
            
        conn.get('http://cn.bing.com', headers=get_headers(referer), timeout=10)
        r = conn.get(bing_url, stream=True, headers=get_headers(referer), timeout=10)
        
        if DEBUG:
            print(f"[DEBUG] Bing响应状态码: {r.status_code}")
            print(f"[DEBUG] Bing响应长度: {len(r.text)}")
            
        emails = search_email(r.text)
        return emails
    except Exception as e:
        if DEBUG:
            print(f"[ERROR] Bing搜索出错: {e}")
        return []

def baidu_search(url,page,key_word):
    try:
        email_list = []
        emails = []
        referer = "https://www.baidu.com/s?wd=email+site%3Abaidu.com&pn=1"
        baidu_url = "https://www.baidu.com/s?wd="+key_word+"+site%3A"+url+"&pn="+str((page-1)*10)
        
        if DEBUG:
            print(f"[DEBUG] 百度搜索URL: {baidu_url}")
            
        conn = requests.session()
        conn.get(referer,headers=get_headers(referer), timeout=10)
        r = conn.get(baidu_url, headers=get_headers(referer), timeout=10)
        
        if DEBUG:
            print(f"[DEBUG] 百度响应状态码: {r.status_code}")
            print(f"[DEBUG] 百度响应长度: {len(r.text)}")
            
        soup = BeautifulSoup(r.text, 'lxml')
        tagh3 = soup.find_all('h3')
        
        if DEBUG:
            print(f"[DEBUG] 找到 {len(tagh3)} 个搜索结果")
            
        for h3 in tagh3:
            link = h3.find('a')
            if link:
                href = link.get('href')
                if href and href.startswith('http'):
                    if DEBUG:
                        print(f"[DEBUG] 访问链接: {href}")
                    try:
                        r = requests.get(href, headers=get_headers(referer), timeout=8)
                        emails = search_email(r.text)
                        if DEBUG and emails:
                            print(f"[DEBUG] 在链接中找到邮箱: {emails}")
                    except Exception as e:
                        if DEBUG:
                            print(f"[ERROR] 访问链接失败: {e}")
                        continue
                    for email in emails:
                        email_list.append(email)
        return email_list
    except Exception as e:
        if DEBUG:
            print(f"[ERROR] 百度搜索出错: {e}")
        return []

def search_email(html):
    # 改进邮箱正则表达式
    emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", html, re.I)
    # 去重
    unique_emails = list(set(emails))
    return unique_emails

if __name__ == '__main__':
    start(sys.argv[1:])