'''
Function:
    cors_attack
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
            'Origin': 'http://127.0.0.1/',
        }
        self.result_text = ""
        self.proxies = proxies

    def vuln(self):
        try:
            result = requests.get(url=self.url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "http://127.0.0.1/" in str(result.headers):
                target = urlparse(self.url)
                if target.query != "":
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在CORS跨域资源共享漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                else:
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在CORS跨域资源共享漏洞\033[0m
                 GET {} HTTP/1.1
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
