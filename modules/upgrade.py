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
import shutil


class up:

    def ghr_upgrade(self):
        try:
            url = "https://mirror.ghproxy.com/https://github.com/spmonkey/GHR/archive/refs/heads/main.zip"
            filename = wget.download(url, "../GHR.zip", bar=False)
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall("../")

            os.remove(filename)
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.recursive_folder(path)
            return True
        except:
            print(" [-] 更新失败，但是不影响使用，如果需要更新，请重新运行：python GHR.py --upgrade\n")
            return False

    def recursive_folder(self, path):
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if item == "__pycache__":
                shutil.rmtree(item_path)
            if os.path.isdir(item_path) and item != "__pycache__":
                self.recursive_folder(item_path)
