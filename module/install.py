'''
Function:
    模块安装
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
import os


def install():
    try:
        upgrade = os.popen("python>nul 2>nul -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
        os.popen("pip3>nul 2>nul uninstall -y urllib3").read()
        os.popen("pip3>nul 2>nul uninstall -y docx").read()
        os.popen("pip3>nul 2>nul uninstall -y chardet").read()
        install_molde = os.popen("pip3>nul 2>nul install urllib3 chardet wget python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
        os.popen("pip3>nul 2>nul install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
        return True
    except:
        try:
            upgrade = os.popen("python3>nul 2>nul -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
            os.popen("pip3>nul 2>nul uninstall -y urllib3").read()
            os.popen("pip3>nul 2>nul uninstall -y docx").read()
            os.popen("pip3>nul 2>nul uninstall -y chardet").read()
            install_molde = os.popen("pip3>nul 2>nul install urllib3 wget chardet python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
            os.popen("pip3>nul 2>nul install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
            return True
        except:
            return False

