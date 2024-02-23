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
import subprocess


def install():
    try:
        result = subprocess.run("python --version", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            if " 3." in result.stdout.decode('utf-8'):
                upgrade = subprocess.run("python>nul 2>nul -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run("pip3>nul 2>nul uninstall -y urllib3", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run("pip3>nul 2>nul uninstall -y docx", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run("pip3>nul 2>nul uninstall -y chardet", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                install_molde = subprocess.run("pip3 install urllib3 chardet wget python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run("pip3>nul 2>nul install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if install_molde.returncode != 0:
                    return False
                else:
                    return True
            else:
                try:
                    upgrade = subprocess.run("python3>nul 2>nul -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run("pip3>nul 2>nul uninstall -y urllib3", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run("pip3>nul 2>nul uninstall -y docx", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run("pip3>nul 2>nul uninstall -y chardet", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    install_molde = subprocess.run("pip3 install urllib3 wget chardet python-docx requests argparse gevent bs4 lxml -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    subprocess.run(
                        "pip3>nul 2>nul install --upgrade requests -i https://pypi.tuna.tsinghua.edu.cn/simple", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if install_molde.returncode != 0:
                        return False
                    else:
                        return True
                except:
                    return False
        else:
            return False
    except:
        return False

