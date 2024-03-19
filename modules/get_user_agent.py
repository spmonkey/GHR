'''
Function:
    ua头切换
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
import random
import os
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_user_agent():
    user_agent_list = open("{}\\library\\user-agents.txt".format(path), "r", encoding="utf-8").readlines()
    return random.choice(user_agent_list).split("\n")[0]
