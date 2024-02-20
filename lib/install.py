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
        upgrade = os.popen("python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
        if "Successfully" in upgrade or "Requirement already" in upgrade:
            pass
        os.popen("pip3 uninstall -y urllib3").read()
        os.popen("pip3 uninstall -y docx").read()
        os.popen("pip3 uninstall -y chardet").read()
        install_molde = os.popen("pip3 install wget python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
        if "Successfully" in install_molde or "Requirement already" in install_molde:
            os.popen("pip3 install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple")
            return True
        else:
            return False
    except:
        try:
            upgrade = os.popen("python3 -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
            if "Successfully" in upgrade or "Requirement already" in upgrade:
                pass
            os.popen("pip3 uninstall -y urllib3").read()
            os.popen("pip3 uninstall -y docx").read()
            os.popen("pip3 uninstall -y chardet").read()
            install_molde = os.popen("pip3 install urllib3 wget chardet python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple").read()
            if "Successfully" in install_molde or "Requirement already" in install_molde:
                os.popen("pip3 install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple")
                return True
            else:
                return False
        except:
            return False

