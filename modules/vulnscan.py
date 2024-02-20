'''
Function:
    vulnscan
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
from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
import os
import sys
import platform
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules import common


class vulnscan:
    def __init__(self, url, target, proxy):
        self.url = url
        self.target = target
        self.q = Queue()
        common._init()
        common.set_value("os", "windows" if "Windows" in platform.system() else "linux")
        common.set_value("pocinfo_dict", common.get_pocinfo_dict())
        self.pocinfo_dict = common.get_value("pocinfo_dict")
        self.results = []
        self.proxies = proxy

    def vuln_queue(self):
        for i in self.pocinfo_dict:
            vulnfile = common.get_value("pocinfo_dict")[i]
            self.q.put(vulnfile)
        return True

    def vuln(self, url):
        while True:
            if self.q.qsize() == 0:
                return
            model = self.q.get_nowait()
            if "poc" in str(model):
                if self.url == self.target:
                    result = model.poc(self.url, self.proxies).main()
                    self.results.append(result)
            else:
                result = model.poc(self.url, self.proxies).main()
                self.results.append(result)

    def main(self):
        pool = Pool(50)
        if self.vuln_queue():
            tasks = [pool.spawn(self.vuln, i) for i in range(50)]
            pool.join()
        return self.results
