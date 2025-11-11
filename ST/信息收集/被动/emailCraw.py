#  邮件爬取

from wsgiref import headers
import requests
from bs4 import BeautifulSoup
import sys
import getopt
import re

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


def launcher(url, pages):
    email_num = []
    key_words = ['email','mail','mailbox','邮件','邮箱','postbox']

    for page in range(1,int(pages)+1):
        for ker_word in key_words:
            bing_emails = bing_search(url,page,ker_word)
            baidu_emails = baidu_search(url,page,ker_word)
            sum_emails = bing_emails + baidu_emails

            for email in sum_emails:
                if email in email_num:
                    pass
                else:
                    print(email)
                    with open('data.txt','a+') as f:
                        f.write(email + '\n')
                    email_num.append(email)
def bing_search(url,page,key_word):
    referer = "http://cn.bing.com/search?q=email+site%3abaidu.com&qs=n&sp=-1&pq=emailsite%3abaidu.com&first=1&FORM=PERE1"

    conn = requests.session()
    
    bing_url = "http://cn.bing.com/search?q=" + key_word + "+site%3a" + url + "&qs=n&sp=-1&pq=" + key_word + "site%3a" + url + "&first=" + str(
        (page-1)*10) + "&FORM=PERE1"
    conn.get('http://cn.bing.com', headers=headers(referer))
    r = conn.get(bing_url, stream=True, headers=headers(referer), timeout=8)
    emails = search_email(r.text)
    return emails



def baidu_search(url,page,key_word):
    email_list = []
    emails = []
    referer = "https://www.baidu.com/s?wd=email+site%3Abaidu.com&pn=1"
    baidu_url = "https://www.baidu.com/s?wd="+key_word+"+site%3A"+url+"&pn="+str((page-1)*10)
    conn = requests.session()
    conn.get(referer,headers=headers(referer))
    r = conn.get(baidu_url, headers=headers(referer))
    soup = BeautifulSoup(r.text, 'lxml')
    tagh3 = soup.find_all('h3')
    for h3 in tagh3:
        href = h3.find('a').get('href')
        try:
            r = requests.get(href, headers=headers(referer),timeout=8)
            emails = search_email(r.text)
        except Exception as e:
            pass
        for email in emails:
            email_list.append(email)
    return email_list

def search_email(html):
    emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+",html,re.I)
    return emails
def headers(referer):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
               'Accept': '*/*',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip,deflate',
               'Referer': referer
               }
    return headers


            
if __name__ == '__main__':

    #定义异常
    try:
        start(sys.argv[1:])
    
    except KeyboardInterrupt:
        print("interrupted by uesr,killing all threads...")

