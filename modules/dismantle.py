'''
Function:
    拆解模块
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
from gevent import monkey;monkey.patch_all()
from gevent.pool import Pool
from urllib.parse import urlparse
import dirmap
import re


class urldismantle:
    def __init__(self, url):
        self.url = url
        self.url_list = []

    def Dismantle(self, paths):
        num = len(paths.split("/")[1:])
        path_list = []
        for i in range(num):
            if "." not in paths.split("/")[1:][i]:
                if path_list != []:
                    path = path_list[i - 1] + "/" + paths.split("/")[1:][i]
                    path_list.append(path)
                else:
                    path_list.append(paths.split("/")[1:][i])
        return path_list

    def dirmap_main(self, url):
        dirmap.dirmap(url).main()

    def main(self):
        url = urlparse(self.url)
        print(url)
        if url.path != "/":
            if len(url.path.split("/")[1:]) >= 1:
                url_list = self.Dismantle(url.path)
                for url_path in url_list:
                    self.url_list.append("{}://{}/{}/".format(url.scheme, url.netloc, url_path))
            else:
                self.url_list.append("{}/".format(self.url))
        else:
            self.url_list.append("{}://{}/".format(url.scheme, url.netloc))
        num = len(self.url_list)
        pool = Pool(num)
        for i in range(num):
            pool.spawn(self.dirmap_main, self.url_list[i])
        pool.join()


