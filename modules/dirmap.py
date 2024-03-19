'''
Function:
    目录扫描
Author:
    spmonkey，夜梓月
Wechat official account：
    中龙 红客突击队
Official website：
    https://www.hscsec.cn/
Email：
    spmonkey@hscsec.cn
Blog:
    https://spmonkey.github.io/
GitHub:
    https://github.com/spmonkey/
'''
# -*- coding: utf-8 -*-
from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
from bs4 import BeautifulSoup
from requests.packages.urllib3 import disable_warnings
from urllib.parse import urlparse
import gevent
import time
import requests
import os
import sys
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules import get_user_agent


class dirmap:
    def __init__(self, url, proxies, thread, order=True):
        self.url = url
        if self.url[-1] != "/" and order:
            self.url += "/"
        self.q = Queue()
        self.order = order
        self.thread = thread
        self.symbol = ['|', '/', '-', '\\', '|', '/', '-', '\\']
        self.path_list = []
        self.over_path = []
        self.flag = False
        if sys.platform.startswith("win"):
            self.dictionarys = open(path + "\\library\\dicc.txt").readlines()
        else:
            self.dictionarys = open(path + "/library/dicc.txt").readlines()
        self.proxies = proxies

    def dictionarys_queue(self):
        for dictionary in self.dictionarys:
            self.q.put(dictionary.split("\n")[0])
        return True

    def dirmap(self, x):
        while True:
            if self.q.qsize() == 0:
                return True
            path = self.q.get_nowait()
            url = self.url + path
            try:
                headers = {
                    'User-Agent': get_user_agent.get_user_agent(),
                }
                result = requests.get(url=url, headers=headers, verify=False, proxies=self.proxies, allow_redirects=False)
                if result.status_code == 200 and url not in self.path_list:
                    self.path_list.append(url)
            except:
                pass

    def crawler(self):
        headers = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        result = requests.get(url=self.url, headers=headers, verify=False, timeout=3, proxies=self.proxies)
        result.encoding = "utf-8"
        soup = BeautifulSoup(result.text, "lxml")
        scripts = soup.find_all("script")
        a_tags = soup.find_all("a")
        links = soup.find_all("link")
        target = urlparse(self.url)
        target_url_netloc = target.netloc
        target_url_scheme = target.scheme
        for script in scripts:
            src = script.get("src")
            if src is not None:
                if src[:1] == "/":
                    src = "{}://{}{}".format(target_url_scheme, target_url_netloc, src)
                else:
                    src = self.url + src
                if src not in self.path_list:
                    self.path_list.append(src)
        for a in a_tags:
            href = a.get("href")
            if href is not None:
                if href[:1] == "/":
                    href = "{}://{}{}".format(target_url_scheme, target_url_netloc, href)
                else:
                    href = self.url + href
                if href not in self.path_list:
                    self.path_list.append(href)
        for link in links:
            href = link.get("href")
            if href is not None:
                if href[:1] == "/":
                    href = "{}://{}{}".format(target_url_scheme, target_url_netloc, href)
                else:
                    href = self.url + href
                if href not in self.path_list:
                    self.path_list.append(href)

    def filtration(self):
        paths = []
        for path in self.path_list:
            if path.count("http:") == 1 and path.count("https:") == 1:
                paths.append(path)
            elif path.count("http:") > 1 or path.count("https:") > 1:
                paths.append(path)
        for path in self.path_list:
            if path not in paths:
                self.over_path.append(path)

    def main(self, count, unfinished):
        if self.order:
            pool = Pool(self.thread)
            jobs = []
            if self.dictionarys_queue():
                for i in range(self.thread):
                    task = pool.spawn(self.dirmap, i)
                    jobs.append(task)
                while not self.flag:
                    if count == 0 and unfinished == 0:
                        for dot in range(0, 8):
                            symbolnum = dot
                            if dot == 7:
                                print(f''' [{self.symbol[symbolnum]}] 正在进行目录扫描{" " * 10}''')
                                sys.stdout.write("\033[F" * 1)
                                time.sleep(1)
                            else:
                                print(f''' [{self.symbol[symbolnum]}] 正在进行目录扫描{"." * (dot + 1)}''')
                                sys.stdout.write("\033[F" * 1)
                                time.sleep(1)
                    else:
                        for dot in range(0, 8):
                            symbolnum = dot
                            if dot == 7:
                                print(f''' [{self.symbol[symbolnum]}] 正在进行目录扫描{" " * 10}
 [+] 已完成url数量：{count}，未完成url数量：{unfinished}''')
                                sys.stdout.write("\033[F" * 2)
                                time.sleep(1)
                            else:
                                print(f''' [{self.symbol[symbolnum]}] 正在进行目录扫描{"." * (dot + 1)}
 [+] 已完成url数量：{count}，未完成url数量：{unfinished}''')
                                sys.stdout.write("\033[F" * 2)
                                time.sleep(1)
                    for job in jobs:
                        if job.ready():
                            self.flag = True
                            break
        print("\r", end="")
        self.crawler()
        self.filtration()
        return self.over_path


