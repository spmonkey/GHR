'''
Function:
    OPTIONS方法检测 低危
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
        target = urlparse(self.url)
        try:
            result = requests.options(url=self.url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if result.status_code == 200 and "Allow" in result.headers:
                self.result_text += """\n        [+]    \033[32m开启了 OPTIONS 方法\033[0m
                 OPTIONS {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                return True
            else:
                return False
        except Exception as e:
            return False

    def main(self):
        if self.vuln():
             return self.result_text
        else:
            return False
