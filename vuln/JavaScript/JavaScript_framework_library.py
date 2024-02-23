'''
Function:
    JavaScript框架库漏洞
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
import re
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
            filename = re.search("jquery-(\d+\.\d+\.\d+)(.*?).js", self.url).group(1)
            if filename <= "3.5.0":
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在JavaScript框架库漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}
                 User-Agent: {}""".format(target.path, target.netloc, self.headers["User-Agent"])
                return True
        except:
            try:
                result = requests.get(url=self.url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                jQuery_version = re.search("v(\d+\.\d+\.\d+)", result.text).group(1)
                if jQuery_version <= "3.5.0":
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在JavaScript框架库漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    return True
                else:
                    pass
            except:
                return False

    def main(self):
        if self.vuln():
             return self.result_text
        else:
            return False


