'''
Function:
    去重模块
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


class duplicate_removal:
    def __init__(self, manages):
        self.manages = manages
        self.result_text = []
        self.result_level = []

    def dr(self):
        for manages in self.manages:
            for manage in manages:
                if manage not in self.result_text and manage != False and manage != []:
                    if type(manage) != list:
                        self.result_text.append(manage)
                        if "JavaScript框架库漏洞" in manage or "Host头攻击" in manage:
                            self.result_level.append("middle")
                        elif "OPTIONS" in manage:
                            self.result_level.append("low")
                        else:
                            self.result_level.append("high")
                    else:
                        for manage_text in manage:
                            self.result_text.append(manage_text)
                            if "JavaScript框架库漏洞" in manage_text or "Host头攻击" in manage_text:
                                self.result_level.append("middle")
                            elif "OPTIONS" in manage_text:
                                self.result_level.append("low")
                            else:
                                self.result_level.append("high")
        return self.result_text, self.result_level
