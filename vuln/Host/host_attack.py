'''
Function:
    Host头攻击
Author:
    花果山
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
            'Host': 'www.baidu.com'
        }
        self.result_text = ""
        self.proxies = proxies

    def vuln(self):
        target = urlparse(self.url)
        try:
            result = requests.get(url=self.url, headers=self.headers, verify=False, timeout=3, allow_redirects=False, proxies=self.proxies)
            if result.status_code < 400:
                self.result_text += "\n        [+]    \033[32m检测到目标站点存在Host头攻击漏洞\033[0m"
                if target.query != "":
                    self.result_text += "\n                 GET {} HTTP/1.1".format(target.path + "?" + target.query)
                else:
                    self.result_text += "\n                 GET {} HTTP/1.1".format(target.path)
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

