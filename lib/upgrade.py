'''
Function:
    自动更新模块
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
import wget
import zipfile
import os


class up:
    def ghr_upgrade(self):
        try:
            url = "https://mirror.ghproxy.com/https://github.com/spmonkey/GHR/archive/refs/heads/main.zip"
            filename = wget.download(url, "../GHR.zip")
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall("../")

            os.remove(filename)
            return True
        except:
            print("\n [-] 更新失败，但是不影响使用，如果需要更新，请重新运行：python GHR.py --upgrade\n")
            return False

