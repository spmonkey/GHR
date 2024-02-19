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
import requests
import os
import sys
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class dirmap:
    def __init__(self, url, proxies, order=True):
        self.url = url
        if self.url[-1] != "/" and order:
            self.url += "/"
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)'
        }
        self.q = Queue()
        self.order = order
        self.path_list = []
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
                return
            path = self.q.get()
            url = self.url + path
            try:
                result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies, allow_redirects=False)
                if result.status_code == 200 and url not in self.path_list:
                    self.path_list.append(url)
            except:
                pass

    def crawler(self):
        result = requests.get(url=self.url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
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
        for path in self.path_list:
            if path.count("http:") > 1 or path.count("https:") > 1:
                self.path_list.remove(path)

    def main(self):
        if self.order:
            pool = Pool(50)
            if self.dictionarys_queue():
                task = [pool.spawn(self.dirmap, i) for i in range(50)]
                pool.join()
        self.crawler()
        self.filtration()
        return self.path_list


