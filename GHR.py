'''
Function:
    start
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
from modules import logo
import sys
logo.logo()

try:
    print(" [*] 正在检测模块库安装及更新，请稍后......")
    from modules import install
    result = install.install()
    if result:
        print(" [+] 模块库安装及更新已完成，请放心使用！\n")
        pass
    else:
        print(" [-] 模块库安装及更新失败！")
        sys.exit()
except:
    print(" [-] 模块库安装及更新失败！")
    sys.exit()

from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
import requests
import os
import warnings;warnings.filterwarnings("ignore")
from requests.packages.urllib3 import disable_warnings;disable_warnings()
from argparse import ArgumentParser

from modules import duplicate_removal
from modules.vulnscan import vulnscan
from modules.dirmap import dirmap
from modules.writeword import WW
from modules.upgrade import up


def argument():
    parser = ArgumentParser()
    try:
        GHR_module = parser.add_argument_group("GHR 常用参数")
        GHR_module.add_argument('-u', '--url', type=str, default=None, help="url，例：--url http://127.0.0.1/")
        GHR_module.add_argument('--nodir', action='store_true', help="禁用目录扫描")
        GHR_module.add_argument('--proxy', type=str, default=None, help="代理设置，例：--proxy 127.0.0.1:10809")
        GHR_module.add_argument('--upgrade', action='store_true', help="更新参数")
        GHR_module.add_argument('-t', '--thread', type=str, default=None, help="线程设置，例：--thread 10 默认线程数为：20")
        args = parser.parse_args()
        return args
    except Exception as e:
        pass


class GHR:
    def __init__(self, args):
        if args.upgrade:
            self.updata()
        try:
            self.url = args.url
            if self.url[-1] != "/" and "?" not in self.url:
                self.url = self.url + "/"
            if args.thread:
                self.thread = args.thread
            else:
                self.thread = 20
            self.headers = {
                'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
            }
            self.q = Queue()
            self.order = args.nodir
            self.url_list = []
            self.results = []
            self.high_cont = 0
            self.middle_cont = 0
            self.low_cont = 0
            self.proxies = {
                "http": args.proxy,
                "https": args.proxy
            }
        except:
            print(" [-] 缺少参数！请使用 -h 或阅读 readme 查看详细的使用方法！\n")
            return
        self.vuln_main()

    def url_queue(self):
        for url in self.url_list:
            self.q.put(url)
        return True

    def web_vuln(self, i):
        while True:
            if self.q.qsize() == 0:
                return
            url = self.q.get_nowait()
            result = vulnscan(url=url, target=self.url, proxy=self.proxies).main()
            self.results.append(result)

    def dirb_scan(self):
        if self.order:
            result = dirmap(self.url, self.proxies, thread=self.thread, order=False).main()
            self.url_list.append(self.url)
            for url in result:
                if url not in self.url_list:
                    self.url_list.append(url)
        else:
            result = dirmap(url=self.url, proxies=self.proxies, thread=self.thread).main()
            self.url_list.append(self.url)
            for url in result:
                if url not in self.url_list:
                    self.url_list.append(url)
        return True

    def updata(self):
        print(" [*] 正在检测更新，请稍后...")
        path = os.getcwd()
        result = up(path).ghr_upgrade()
        if result:
            print(" [+] 更新已完成\n")
            sys.exit()

    def test_before_use(self):
        try:
            result = requests.get(url=self.url, headers=self.headers, timeout=3, verify=False)
            if result.status_code <= 500:
                print("\033[32m{} --> {}\033[0m".format(self.url, result.status_code))
                return True
            else:
                print("\033[31m{} --> {}\033[0m".format(self.url, result.status_code))
                return False
        except:
            print("\033[31m{} time out!\033[0m".format(self.url))
            return False

    def write_main(self, result):
        WW(self.url, result_list=result).main()

    def vuln_main(self):
        pool = Pool(int(self.thread))
        if self.test_before_use():
            if self.dirb_scan():
                if self.url_queue():
                    tasks = [pool.spawn(self.web_vuln, i) for i in range(int(self.thread))]
                    pool.join()
        # 去重
        result = duplicate_removal.duplicate_removal(self.results).dr()
        result_text = result[0]
        result_level = result[1]
        for result in result_text:
            print(result)
        for level in result_level:
            if level == "high":
                self.high_cont += 1
            elif level == "middle":
                self.middle_cont += 1
            elif level == "low":
                self.low_cont += 1
        if self.low_cont != 0 or self.middle_cont != 0 or self.high_cont != 0:
            print("\n共发现 \033[31m高危漏洞：{}\033[0m，\033[33m中危漏洞：{}\033[0m，\033[32m低危漏洞：{}\033[0m".format(self.high_cont, self.middle_cont, self.low_cont))
            print("")
            print("正在生成报告，请稍后...")
            self.write_main(result_text)
        else:
            print("\n共发现 \033[31m高危漏洞：{}\033[0m，\033[33m中危漏洞：{}\033[0m，\033[32m低危漏洞：{}\033[0m\n当前系统很安全".format(self.high_cont, self.middle_cont, self.low_cont))
        print("")


if __name__ == '__main__':
    args = argument()
    GHR(args=args)

