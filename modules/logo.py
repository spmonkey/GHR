'''
Function:
    logo程序
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
import os, sys


def logo():
    path = os.getcwd()
    if sys.platform.startswith("win"):
        version = open("{}\\library\\version.txt".format(path), 'r', encoding="utf-8").readlines()[0].split("\n")[0]
    else:
        version = open("{}/library/version.txt".format(path), 'r', encoding="utf-8").readlines()[0].split("\n")[0]
    logo = """
  ________       .__       .___                      .__                                    .___ __________           .___
 /  _____/  ____ |  |    __| _/____   ____           |  |__   ____   ____ ______   ____   __| _/ \\______   \\ ____   __| _/
/   \\  ___ /  _ \\|  |   / __ |/ __ \\ /    \\   ______ |  |  \\ /  _ \\ /  _ \\\\____ \\_/ __ \\ / __ |   |       _//  _ \\ / __ | 
\\    \\_\\  (  <_> )  |__/ /_/ \\  ___/|   |  \\ /_____/ |   Y  (  <_> |  <_> )  |_> >  ___// /_/ |   |    |   (  <_> ) /_/ | 
 \\______  /\\____/|____/\\____ |\\___  >___|  /         |___|  /\\____/ \\____/|   __/ \\___  >____ |   |____|_  /\\____/\\____ | 
        \\/                  \\/    \\/     \\/               \\/              |__|        \\/     \\/          \\/            \\/    (V{})


花果山出品
""".format(version)
    print(logo)
