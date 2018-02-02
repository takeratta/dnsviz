#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2017 Casey Deccio
#
# DNSViz is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DNSViz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import unicode_literals

import hashlib
import hmac
import re

from dns.edns import Option

COOKIE_ALG_STR_RE = re.compile(r'(.*?)({([a-zA-Z0-9-]+)\((CS|SC)\)})?')
# example: hmac-sha1-64{

class CookieJarClassNotFound(Exception):
    pass

class CookieAlgorithmStringInvalid(Exception):
    pass

class DNSCookieJarCollection:
    def __init__(self, client, secret):
        self.client = client
        self.secret = secret
        self._cookie_jars = {}

    def cookie_jar_from_text(self, s):
        if s not in self._cookie_jars:
            match = COOKIE_ALG_STR_RE.search(s)
            if match is None:
                raise CookieAlgorithmStringInvalid('Invalid cookie algorithm string: %s' % s)
            try:
                cls = _name_jar_mapping[match.group(1)]
            except KeyError:
                raise CookieJarClassNotFound('Cookie Jar class not found: %s' % match.group(1))
            self._cookie_jars[s] = cls(self.client, self.secret, match.group(2))
        return self._cookie_jars[s]

    def get_cookie_opt(self, s, server):
        return self.cookie_jar_from_text(s).get_cookie_opt(server)

class DNSCookieJar(object):
    algorithm = None
    truncate_at = None

    def __init__(self, client, secret, ordering):
        if self.__class__ == DNSCookieJar:
            raise NotImplemented

        self._field_map = {
                'C': client._ipaddr_bytes,
                'S': None,
        }
        self.client = client
        self.secret = secret
        self._ordering = ordering
        self._cache = {}

    def get_cookie_opt(self, server):
        if server not in self._cache:
            field_map = self._field_map.copy()
            field_map['S'] = server._ipaddr_bytes
            msg = field_map[self._ordering[0]] + \
                    field_map[self._ordering[1]]
            hm = hmac.new(self.secret, msg, self.algorithm)
            val = dns.edns.GenericOption(10, hm.digest()[:self.truncate_at])
            self._cache[server] = val
        return self._cache[server]

    def to_text(self):
        return '%s(%s)' % (self.base_text, self._ordering)

class HMACSha164CookieJar(DNSCookieJar):
    algorithm = hashlib.sha1
    truncate_at = 8
    base_text = 'hmac-sha1-64'

class HMACSha25664CookieJar(DNSCookieJar):
    algorithm = hashlib.sha256
    truncate_at = 8
    base_text = 'hmac-sha256-64'

_name_jar_mapping = {
        'hmac-sha1-64': HMACSha164CookieJar,
        'hmac-sha256-64': HMACSha25664CookieJar,
}

class DNSCookieTemplate(Option):
    COOKIE_ID = 10

    #def __init__(self, template):
    #    if 
    #    client_cookie = COOKIE_ALG_STR_RE.search(encoded_data)
    #    self.data = data
#
#        super(DNSCookie, self).__init__(10, )

    #@classmethod
    #def from_encoded_data(cls, encoded_data):
    #    for i in 
    #    if 

