'''
Function:
    wafscaner
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
from __future__ import print_function

import io
import logging
import os
import random
import re
import sys
from wafw00f.manager import load_plugins
from wafw00f.wafprio import wafdetectionsprio
from wafw00f.lib.evillib import urlParser, waftoolsengine


class WAFW00F(waftoolsengine):

    xsstring = '<script>alert("XSS");</script>'
    sqlistring = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
    lfistring = '../../../../etc/passwd'
    rcestring = '/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'
    xxestring = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'

    def __init__(self, target='www.example.com', debuglevel=0, path='/',
                 followredirect=True, extraheaders={}, proxies=None):

        self.log = logging.getLogger('wafw00f')
        self.attackres = None
        waftoolsengine.__init__(self, target, debuglevel, path, proxies, followredirect, extraheaders)
        self.knowledge = dict(generic=dict(found=False, reason=''), wafname=list())
        self.rq = self.normalRequest(self.headers)

    def normalRequest(self, headers):
        return self.Request(headers=headers)

    def customRequest(self, headers):
        return self.Request(headers=headers)

    def nonExistent(self, headers):
        return self.Request(headers=headers, path=self.path + str(random.randrange(100, 999)) + '.html')

    def xssAttack(self, headers):
        return self.Request(headers=headers, path=self.path, params= {'s': self.xsstring})

    def xxeAttack(self, headers):
        return self.Request(headers=headers, path=self.path, params= {'s': self.xxestring})

    def lfiAttack(self, headers):
        return self.Request(headers=headers, path=self.path + self.lfistring)

    def centralAttack(self, headers):
        return self.Request(headers=headers, path=self.path, params={'a': self.xsstring, 'b': self.sqlistring, 'c': self.lfistring})

    def sqliAttack(self, headers):
        return self.Request(headers=headers, path=self.path, params= {'s': self.sqlistring})

    def oscAttack(self, headers):
        return self.Request(headers=headers, path=self.path, params= {'s': self.rcestring})

    def performCheck(self, request_method):
        r = request_method(self.headers)
        if r is None:
            raise RequestBlocked()
        return r

    attcom = [xssAttack, sqliAttack, lfiAttack]
    attacks = [xssAttack, xxeAttack, lfiAttack, sqliAttack, oscAttack]

    def genericdetect(self):
        reason = ''
        reasons = ['Blocking is being done at connection/packet level.',
                   'The server header is different when an attack is detected.',
                   'The server returns a different response code when an attack string is used.',
                   'It closed the connection for a normal request.',
                   'The response was different when the request wasn\'t made from a browser.'
                ]
        try:
            resp1 = self.performCheck(self.normalRequest)
            if 'User-Agent' in self.headers:
                self.headers.pop('User-Agent')
            resp3 = self.customRequest(headers=self.headers)
            if resp3 is not None and resp1 is not None:
                if resp1.status_code != resp3.status_code:
                    self.log.info('Server returned a different response when request didn\'t contain the User-Agent header.')
                    reason = reasons[4]
                    reason += '\r\n'
                    reason += 'Normal response code is "%s",' % resp1.status_code
                    reason += ' while the response code to a modified request is "%s"' % resp3.status_code
                    self.knowledge['generic']['reason'] = reason
                    self.knowledge['generic']['found'] = True
                    return True

            resp2 = self.performCheck(self.xssAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('Server returned a different response when a XSS attack vector was tried.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to cross-site scripting attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

            resp2 = self.performCheck(self.lfiAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('Server returned a different response when a directory traversal was attempted.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to a file inclusion attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

            resp2 = self.performCheck(self.sqliAttack)
            if resp1.status_code != resp2.status_code:
                self.log.info('Server returned a different response when a SQLi was attempted.')
                reason = reasons[2]
                reason += '\r\n'
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += ' while the response code to a SQL injection attack is "%s"' % resp2.status_code
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

            normalserver, attackresponse_server = '', ''
            response = self.attackres
            if 'server' in resp1.headers:
                normalserver = resp1.headers.get('Server')
            if response is not None and 'server' in response.headers:
                attackresponse_server = response.headers.get('Server')
            if attackresponse_server != normalserver:
                self.log.info('Server header changed, WAF possibly detected')
                self.log.debug('Attack response: %s' % attackresponse_server)
                self.log.debug('Normal response: %s' % normalserver)
                reason = reasons[1]
                reason += '\r\nThe server header for a normal response is "%s",' % normalserver
                reason += ' while the server header a response to an attack is "%s",' % attackresponse_server
                self.knowledge['generic']['reason'] = reason
                self.knowledge['generic']['found'] = True
                return True

        except RequestBlocked:
            self.knowledge['generic']['reason'] = reasons[0]
            self.knowledge['generic']['found'] = True
            return True
        return False

    def matchHeader(self, headermatch, attack=False):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return

        header, match = headermatch
        headerval = r.headers.get(header)
        if headerval:
            if header == 'Set-Cookie':
                headervals = headerval.split(', ')
            else:
                headervals = [headerval]
            for headerval in headervals:
                if re.search(match, headerval, re.I):
                    return True
        return False

    def matchStatus(self, statuscode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        if r.status_code == statuscode:
            return True
        return False

    def matchCookie(self, match, attack=False):
        return self.matchHeader(('Set-Cookie', match), attack=attack)

    def matchReason(self, reasoncode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        if str(r.reason) == reasoncode:
            return True
        return False

    def matchContent(self, regex, attack=True):
        if attack:
            r = self.attackres
        else:
            r = self.rq
        if r is None:
            return
        if re.search(regex, r.text, re.I):
            return True
        return False

    wafdetections = dict()

    plugin_dict = load_plugins()
    result_dict = {}
    for plugin_module in plugin_dict.values():
        wafdetections[plugin_module.NAME] = plugin_module.is_waf
    checklist = wafdetectionsprio
    checklist += list(set(wafdetections.keys()) - set(checklist))

    def identwaf(self, findall=False):
        detected = list()
        try:
            self.attackres = self.performCheck(self.centralAttack)
        except RequestBlocked:
            return detected
        for wafvendor in self.checklist:
            self.log.info('Checking for %s' % wafvendor)
            if self.wafdetections[wafvendor](self):
                detected.append(wafvendor)
                if not findall:
                    break
        self.knowledge['wafname'] = detected
        return detected

def calclogginglevel(verbosity):
    default = 40
    level = default - (verbosity * 10)
    if level < 0:
        level = 0
    return level

def buildResultRecord(url, waf):
    result = {}
    result['url'] = url
    if waf:
        result['detected'] = True
        if waf == 'generic':
            result['firewall'] = 'Generic'
            result['manufacturer'] = 'Unknown'
        else:
            result['firewall'] = waf.split('(')[0].strip()
            result['manufacturer'] = waf.split('(')[1].replace(')', '').strip()
    else:
        result['detected'] = False
        result['firewall'] = 'None'
        result['manufacturer'] = 'None'
    return result

def getTextResults(res=None):
    keys = ('detected')
    res = [({key: ba[key] for key in ba if key not in keys}) for ba in res]
    rows = []
    for dk in res:
        p = [str(x) for _, x in dk.items()]
        rows.append(p)
    for m in rows:
        m[1] = '%s (%s)' % (m[1], m[2])
        m.pop()
    defgen = [
        (max([len(str(row[i])) for row in rows]) + 3)
        for i in range(len(rows[0]))
    ]
    rwfmt = "".join(["{:>"+str(dank)+"}" for dank in defgen])
    textresults = []
    for row in rows:
        textresults.append(rwfmt.format(*row))
    return textresults

def disableStdOut():
    sys.stdout = None

def enableStdOut():
    sys.stdout = sys.__stdout__

def getheaders(fn):
    headers = {}
    if not os.path.exists(fn):
        logging.getLogger('wafw00f').critical('Headers file "%s" does not exist!' % fn)
        return
    with io.open(fn, 'r', encoding='utf-8') as f:
        for line in f.readlines():
            _t = line.split(':', 2)
            if len(_t) == 2:
                h, v = map(lambda x: x.strip(), _t)
                headers[h] = v
    return headers

class RequestBlocked(Exception):
    pass

def main(args, proxy):
    extraheaders = {}
    findall = False
    targets = [args]
    results = []
    for target in targets:
        if not target.startswith('http'):
            target = 'https://' + target
        pret = urlParser(target)
        (hostname, _, path, _, _) = pret
        proxies = proxy
        attacker = WAFW00F(target, debuglevel=0, path=path,
                    followredirect=True, extraheaders=extraheaders,
                        proxies=proxies)
        if attacker.rq is None:
            continue
        waf = attacker.identwaf(findall)
        if len(waf) > 0:
            for i in waf:
                results.append(buildResultRecord(target, i))
        if (findall) or len(waf) == 0:
            if attacker.genericdetect():
                results.append(buildResultRecord(target, 'generic'))
                return True
            else:
                results.append(buildResultRecord(target, None))
                return False


