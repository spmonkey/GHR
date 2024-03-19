'''
Function:
    main
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
import os, sys
from requests.packages.urllib3 import disable_warnings
disable_warnings()
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
from modules import get_user_agent


class versioncheck:
    def __init__(self):
        self.headers = {
            'User-Agent': get_user_agent.get_user_agent(),
        }
        path = os.getcwd()
        if sys.platform.startswith("win"):
            self.old_version = open("{}\\library\\version.txt".format(path), 'r', encoding="utf-8").readlines()[0].split("\n")[0]
        else:
            self.old_version = open("{}/library/version.txt".format(path), 'r', encoding="utf-8").readlines()[0].split("\n")[0]

    def version_to_tuple(self, version_str):
        return tuple(map(int, version_str.split('.')))

    def check(self):
        url = "https://mirror.ghproxy.com/https://github.com/spmonkey/GHR/blob/main/library/version.txt"
        new_version = requests.get(url=url, headers=self.headers, verify=False).text
        return new_version

    def main(self):
        version = self.check()
        version_tuple = self.version_to_tuple(version)
        if self.version_to_tuple(self.old_version) < version_tuple:
            print(" [+] 存在新版本，请运行命令更新：python GHR.py --upgrade 或者 python3 GHR.py --upgrade\n")
        else:
            print(" [+] 当前版本为最新版！\n")

