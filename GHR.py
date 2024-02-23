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
        print(" [-] 模块库安装及更新失败！请使用python3运行该程序！")
        sys.exit()
except:
    print(" [-] 模块库安装及更新失败！请使用python3运行该程序！")
    sys.exit()

from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from gevent.queue import Queue
import requests
import os
import re
import time
import warnings;warnings.filterwarnings("ignore")
from requests.packages.urllib3 import disable_warnings;disable_warnings()

try:
    print(" [*] 正在检测工具是否为最新版，请稍后......")
    from modules.versioncheck import versioncheck
    versioncheck().main()
except:
    pass

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
        GHR_module.add_argument('-u', '--url', type=str, default=None, help="url，例：--url http://127.0.0.1/，-u http://127.0.0.1/")
        GHR_module.add_argument('-f', '--file', type=str, default=None, help="url文件，例：--file url.txt，-f url.txt")
        GHR_module.add_argument('--nodir', action='store_true', help="禁用目录扫描")
        GHR_module.add_argument('--proxy', type=str, default=None, help="代理设置，例：--proxy 127.0.0.1:10809")
        GHR_module.add_argument('--upgrade', action='store_true', help="更新参数")
        GHR_module.add_argument('-t', '--thread', type=str, default=None, help="线程设置，例：--thread 10 默认线程数为：20，-t 10 默认线程数为：20")
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
            self.filename = args.file
            if self.filename is not None:
                if "\\" in self.filename:
                    self.filename = re.sub("\\\\", "\\\\\\\\", self.filename)
                self.file = open(self.filename, "r", encoding='utf-8').readlines()
            if self.url is not None:
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
            self.symbol = ['|', '/', '-', '\\', '|', '/', '-', '\\']
            self.flag = False
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

    def web_vuln(self, target):
        while True:
            if self.q.qsize() == 0:
                return
            url = self.q.get_nowait()
            result = vulnscan(url=url, target=target, proxy=self.proxies).main()
            self.results.append(result)

    def dirb_scan(self, target, count, unfinished):
        if self.order:
            result = dirmap(target, self.proxies, thread=self.thread, order=False).main(count, unfinished)
            self.url_list.append(target)
            for url in result:
                if url not in self.url_list:
                    self.url_list.append(url)
        else:
            result = dirmap(url=target, proxies=self.proxies, thread=self.thread).main(count, unfinished)
            self.url_list.append(target)
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

    def test_before_use(self, url):
        try:
            result = requests.get(url=url, headers=self.headers, timeout=3, verify=False)
            if result.status_code <= 500:
                print("\033[32m{} --> {}\033[0m".format(url, result.status_code))
                return True
            else:
                print("\033[31m{} --> {}\033[0m".format(url, result.status_code))
                return False
        except:
            print("\033[31m{} time out!\033[0m".format(url))
            return False

    def write_main(self, url, result):
        WW(url, result_list=result).main()

    def vuln_main(self):
        pool = Pool(int(self.thread))
        jobs = []
        if self.filename is not None:
            OL = len(self.file)
            count = 0
            for filename in self.file:
                url = filename.split("\n")[0]
                unfinished = OL - count
                if self.test_before_use(url):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    self.dirb_scan(url, count, unfinished)
                if self.url_queue():
                    for i in range(int(self.thread)):
                        tasks = pool.spawn(self.web_vuln, url)
                        jobs.append(tasks)
                    while not self.flag:
                        for dot in range(0, 8):
                            symbolnum = dot
                            if dot == 7:
                                print(f''' [{self.symbol[symbolnum]}] 正在扫描{" " * 10}
 [+] 已完成url数量：{count}，未完成url数量：{unfinished}''')
                                sys.stdout.write("\033[F" * 2)
                                time.sleep(1)
                            else:
                                print(f''' [{self.symbol[symbolnum]}] 正在扫描{'.' * (dot + 1)}
 [+] 已完成url数量：{count}，未完成url数量：{unfinished}''')
                                sys.stdout.write("\033[F" * 2)
                                time.sleep(1)
                        if all([job.ready() for job in jobs]):
                            self.flag = True
                            break
                # 去重
                result = duplicate_removal.duplicate_removal(self.results).dr()
                result_text = result[0]
                result_level = result[1]
                for level in result_level:
                    if level == "high":
                        self.high_cont += 1
                    elif level == "middle":
                        self.middle_cont += 1
                    elif level == "low":
                        self.low_cont += 1
                if self.low_cont != 0 or self.middle_cont != 0 or self.high_cont != 0:
                    self.write_main(url, result_text)
                print(" " * 100)
                count += 1
                self.url_list = []
                self.results = []
                self.high_cont = 0
                self.middle_cont = 0
                self.low_cont = 0
                self.flag = False
        else:
            if self.test_before_use(self.url):
                sys.stdout.write("\n")
                self.dirb_scan(self.url, count=0, unfinished=0)
            if self.url_queue():
                for i in range(int(self.thread)):
                    tasks = pool.spawn(self.web_vuln, self.url)
                    jobs.append(tasks)
                while not self.flag:
                    for dot in range(0, 8):
                        symbolnum = dot
                        if dot == 7:
                            print(f''' [{self.symbol[symbolnum]}] 正在扫描{" " * 10}''')
                            sys.stdout.write("\033[F" * 1)
                            time.sleep(1)
                        else:
                            print(f''' [{self.symbol[symbolnum]}] 正在扫描{"." * (dot + 1)}''')
                            sys.stdout.write("\033[F" * 1)
                            time.sleep(1)
                    for job in jobs:
                        if job.ready():
                            self.flag = True
                            break
            sys.stdout.write("\r" + " " * 15)
            sys.stdout.flush()
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
                self.write_main(self.url, result_text)
            else:
                print("\n共发现 \033[31m高危漏洞：{}\033[0m，\033[33m中危漏洞：{}\033[0m，\033[32m低危漏洞：{}\033[0m\n当前系统很安全".format(self.high_cont, self.middle_cont, self.low_cont))
            print("")


if __name__ == '__main__':
    args = argument()
    GHR(args=args)

