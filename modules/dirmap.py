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
from bs4 import BeautifulSoup
from requests.packages.urllib3 import disable_warnings
from urllib.parse import urlparse
import datetime
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
        self.stop = 0

    def dirmap(self, path):
        url = self.url + path
        self.stop += 1
        print("\r\033[34m [*] \033[0m[{}] 当前目录探测进度：{}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.stop), end="")
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
        result = requests.get(url=self.url, headers=headers, verify=False, proxies=self.proxies)
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

    def main(self):
        print("\033[34m [*] \033[0m[{}] 正在进行目录探测，请稍后...".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        if self.order:
            pool = Pool(self.thread)
            pool.map(self.dirmap, self.dictionarys)
        print("\r", end="")
        self.crawler()
        self.filtration()
        print("\033[32m [+] \033[0m[{}] 目录探测已完成".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + " " * 100 + "\n")
        return self.over_path


