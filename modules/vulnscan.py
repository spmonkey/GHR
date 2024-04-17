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
import time
import platform
import datetime
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
        self.count = 0

    def vuln_queue(self):
        for i in self.pocinfo_dict:
            vulnfile = common.get_value("pocinfo_dict")[i]
            self.q.put(vulnfile)
        return True

    def vuln(self, url):
        while not self.q.empty():
            model = self.q.get()
            # model_text = re.search("module (.*) from", str(model)).group(1)
            if "poc" in str(model) or "redirection" in str(model):
                if self.url == self.target:
                    result = model.poc(self.url, self.proxies).main()
                    self.results.append(result)
            else:
                result = model.poc(self.url, self.proxies).main()
                self.results.append(result)
            self.count += 1
            print("\r\033[34m [*] \033[0m[{}] 当前漏洞检测进度：{}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.count), end="")
            time.sleep(1)

    def main(self):
        pool = Pool(50)
        if self.vuln_queue():
            tasks = [pool.spawn(self.vuln, i) for i in range(50)]
            pool.join()
        print("\r", end="")

        return self.results
