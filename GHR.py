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
    from gevent import monkey;monkey.patch_all(thread=False)
    from gevent.pool import Pool
    from gevent.queue import Queue
    import gevent
    import requests
    import os
    import re
    import time
    import itertools
    import datetime
    import random
    import warnings;warnings.filterwarnings("ignore")
    from urllib.parse import urlparse
    from requests.packages.urllib3 import disable_warnings;disable_warnings()

    from argparse import ArgumentParser
    from modules import duplicate_removal
    from modules.vulnscan import vulnscan
    from modules.dirmap import dirmap
    from modules.writeword import WW
    from modules.upgrade import up
    from modules import wafscaner
except Exception as e:
    print(e)
    print(" [-] 还有模块未安装，请在当前目录下运行：pip install -r requirements.txt，安装模块。")
    sys.exit()

try:
    print(" [*] 正在检测工具是否为最新版，请稍后......")
    from modules.versioncheck import versioncheck
    versioncheck().main()
except:
    pass


def argument():
    parser = ArgumentParser()
    try:
        GHR_module = parser.add_argument_group("GHR 常用参数")
        GHR_module.add_argument('-u', '--url', type=str, default=None, help="url，例：--url http://127.0.0.1/，-u http://127.0.0.1/")
        GHR_module.add_argument('-f', '--file', type=str, default=None, help="url文件，例：--file url.txt，-f url.txt")
        GHR_module.add_argument('--nodir', action='store_true', help="禁用目录扫描")
        GHR_module.add_argument('--proxy', type=str, default=None, help="代理设置，例：--proxy 127.0.0.1:10809")
        GHR_module.add_argument('--upgrade', action='store_true', help="更新参数")
        GHR_module.add_argument('--list', action='store_true', help="更新参数")
        GHR_module.add_argument('-t', '--thread', type=str, default=None, help="线程设置，例：--thread 10 默认线程数为：20，-t 10 默认线程数为：20")
        args = parser.parse_args()
        return args
    except Exception as e:
        pass


def get_user_agent():
    user_agent_list = [
        {'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)'},
        {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; en) Opera 11.00'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; de; rv:1.9.0.2) Gecko/2008092313 Ubuntu/8.04 (hardy) Firefox/3.0.2'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-GB; rv:1.9.1.15) Gecko/20101027 Fedora/3.5.15-1.fc12 Firefox/3.5.15'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.551.0 Safari/534.10'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.2) Gecko/2008092809 Gentoo Firefox/3.0.2'},
        {'User-Agent': 'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/7.0.544.0'},
        {'User-Agent': 'Opera/9.10 (Windows NT 5.2; U; en)'},
        {'User-Agent': 'Mozilla/5.0 (iPhone; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko)'},
        {'User-Agent': 'Opera/9.80 (X11; U; Linux i686; en-US; rv:1.9.2.3) Presto/2.2.15 Version/10.10'},
        {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5'},
        {'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9b3) Gecko/2008020514 Firefox/3.0b3'},
        {'User-Agent': 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_4_11; fr) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16'},
        {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_6; en-US) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20'},
        {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)'},
        {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.0; X11; Linux x86_64; en) Opera 9.60'},
        {'User-Agent': 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_2; en-US) AppleWebKit/533.4 (KHTML, like Gecko) Chrome/5.0.366.0 Safari/533.4'},
        {'User-Agent': 'Mozilla/5.0 (Windows NT 6.0; U; en; rv:1.8.1) Gecko/20061208 Firefox/2.0.0 Opera 9.51'}
    ]
    return random.choice(user_agent_list)


class GHR:
    def __init__(self, args, start_time):
        if args.upgrade:
            self.updata()
        try:
            self.url = args.url
            self.filename = args.file
            if self.filename is not None:
                if "\\" in self.filename:
                    self.filename = re.sub("\\\\", "\\\\\\\\", self.filename)
                self.file = open(self.filename, "r", encoding='utf-8').readlines()
            if args.thread:
                self.thread = args.thread
            else:
                self.thread = 20
            self.thread = int(self.thread)
            self.headers = get_user_agent()
            self.q = Queue()
            self.order = args.nodir
            self.start_time = start_time
            self.url_list = []
            self.results = []
            self.high_cont = 0
            self.middle_cont = 0
            self.low_cont = 0
            self.cont = 0
            self.proxies = {
                "http": args.proxy,
                "https": args.proxy
            }
        except Exception as e:
            print(e)
            print(" [-] 缺少参数！请使用 -h 或阅读 readme 查看详细的使用方法！\n")
            return
        self.vuln_main()

    def wafscanner(self):
        print("\n [*] 正在进行网站waf检测，请稍等...")
        result = wafscaner.main(args=self.url, proxy=self.proxies)
        if result:
            choice = input(" [+] 站点似乎支持WAF或某种安全解决方案，是否继续？[Y/N] ").upper()
            print("")
            if choice == "N":
                sys.exit()
        else:
            print(" [+] 未检测到WAF\n")

    def url_queue(self):
        for url in self.url_list:
            self.q.put(url)
        return True

    def web_vuln(self, all):
        url, target = all
        self.cont += 1
        result = vulnscan(url=url, target=target, proxy=self.proxies, url_num=self.cont).main()
        self.results.append(result)

    def dirb_scan(self, target):
        self.url_list.append(target)
        parsed_url = urlparse(target)
        path = parsed_url.path
        if '.' in path.split('/')[-1]:
            path_without_file = '/'.join(path.split('/')[:-1]) + '/'
        else:
            path_without_file = path
        new_url = f"{parsed_url.scheme}://{parsed_url.netloc}{path_without_file}"
        if self.order:
            result = dirmap(new_url, self.proxies, thread=self.thread, order=False).main()
            for url in result:
                if url not in self.url_list:
                    self.url_list.append(url)
        else:
            result = dirmap(url=new_url, proxies=self.proxies, thread=self.thread).main()
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
            result = requests.get(url=url, headers=self.headers, proxies=self.proxies, verify=False)
            if result.status_code <= 500:
                print("\033[32m{} --> {}\033[0m".format(url, result.status_code))
                return True
            else:
                print("\033[31m{} --> {}\033[0m".format(url, result.status_code))
                return False
        except Exception as e:
            print("\033[31m{} time out!\033[0m".format(url))
            return False

    def write_main(self, url, result):
        WW(url, result_list=result, start_time=self.start_time).main()

    def vuln_main(self):
        pool = Pool(self.thread)
        jobs = []
        if self.filename is not None:
            for filename in self.file:
                url = filename.split("\n")[0]
                if self.test_before_use(url):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    self.dirb_scan(url)
                if self.url_queue():
                    for i in range(int(self.thread)):
                        tasks = pool.spawn(self.web_vuln, url)
                        jobs.append(tasks)
                    gevent.joinall(jobs)
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
                self.url_list = []
                self.results = []
                self.high_cont = 0
                self.middle_cont = 0
                self.low_cont = 0
        elif self.url is not None:
            if self.test_before_use(self.url):
                self.wafscanner()
                sys.stdout.write("\n")
                self.dirb_scan(self.url)
                print("\033[32m [+] \033[0m[{}] 共找到 {} 条路径\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(self.url_list)) + " " * 100 + "\n")
                print("\033[34m [*] \033[0m[{}] 正在进行漏洞检测，请稍后...".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                pool.map(self.web_vuln, list(itertools.product(self.url_list, [self.url])))
                print("\033[32m [+] \033[0m[{}] 漏洞检测已完成".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + " " * 100 + "\n")
            sys.stdout.write("\r" + " " * 100)
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
        else:
            print(" [-] 缺少参数！请使用 -h 或阅读 readme 查看详细的使用方法！\n")
            return


if __name__ == '__main__':
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    args = argument()
    GHR(args=args, start_time=start_time)