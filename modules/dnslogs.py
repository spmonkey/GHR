'''
Function:
    dnslog模块
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
'''
# -*- coding: utf-8 -*-
import requests
import re
import os
import sys
from requests.packages.urllib3 import disable_warnings
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules import get_user_agent


class dnslogs:
    def __init__(self, proxies):
        self.proxies = proxies

    def get_dnslog(self):
        url = "http://dnslog.cn/getdomain.php"
        headers = {
            'User-Agent': get_user_agent.get_user_agent(),
            'Connection': 'close'
        }
        try:
            result = requests.get(url=url, proxies=self.proxies, headers=headers, verify=False)
            cookie = re.search("(.*);", result.headers.get('Set-Cookie')).group(1)
            return result.text, cookie
        except:
            return False

    def get_result(self, cookie):
        url = "http://dnslog.cn/getrecords.php"
        headers = {
            'User-Agent': get_user_agent.get_user_agent(),
            'Cookie': cookie,
            'Connection': 'close'
        }
        try:
            result = requests.get(url=url, proxies=self.proxies, headers=headers, verify=False)
            return result.text
        except:
            return False