# -*- coding: utf-8 -*-
############################################################################
#
# Copyright © 2014, 2015, 2016 OnlineGroups.net and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
# Original software part of https://github.com/groupserver/gs.dmarc/
#
# This has been modified from the original software.
# 01/24/2017 Valimail Inc
# Contact: Gene Shuman <gene@valimail.com>
#
############################################################################
from __future__ import absolute_import, unicode_literals, print_function
from pkg_resources import resource_filename  # Part of setuptools
try:
    # typing is needed by mypy, but is unused otherwise
    from typing import Dict, Text  # noqa: F401
except ImportError:
    pass
from dns.resolver import (query, NXDOMAIN, NoAnswer, NoNameservers)
from publicsuffix import PublicSuffixList
import sys

def answer_to_dict(answer):
    # type: (Text) -> Dict[unicode, unicode]
    '''Turn the DNS DMARC answer into a dict of tag:value pairs.'''
    a = answer.strip('"').strip(' ')
    rawTags = [t.split('=') for t in a.split(';') if t]
    retval = {t[0].strip(): t[1].strip() for t in rawTags}
    return retval

def dns_query(name):
    try:
        return query(name, 'TXT')
    except (NXDOMAIN, NoAnswer, NoNameservers):
        return None

def lookup_receiver_record(host, dnsfunc=dns_query):
    # type: (str), dnsfunc(optional) -> Dict[unicode, unicode]
    '''Lookup the reciever policy for a host
    :param str host: The host to query. The *actual* host that is queried has
                 ``_dmarc.`` prepended to it.
    :param dnsfunc.  a function from domain names to txt records for DNS lookup
    :returns: The DMARC receiver record for the host. If there is no published
          record then None is returned.
    :rtype: {tag => value}
    '''

    dmarcHost = '_dmarc.{0}'.format(host)

    answer = dnsfunc(dmarcHost)

    # This is because dns_query returns a dns.resolver.Answer object while the
    # test suite dnsfunc returns a string (which does not have quotes on it
    # like the dns.resolver object.
    if dnsfunc != dns_query:
        if answer:
            answer = ['"' + answer + '"']

    if not answer:
        return {}
    else:
        # Check that v= field is the first one in the answer (which is in
        # double quotes) as per Section 7.1 (5):
        #     In particular, the "v=DMARC1" tag is mandatory and MUST appear
        #     first in the list. Discard any that do not pass this test.
        # http://tools.ietf.org/html/draft-kucherawy-dmarc-base-04#section-7.1
        if str(answer[0])[:9] == '"v=DMARC1':
            tags = answer_to_dict(str(answer[0]))
            return tags
        else:
            return {} # maybe raise exception instead?


def receiver_record(host, dnsfunc=dns_query):
    # type: (str), dnsfunc(optional) -> (Dict[unicode, unicode], is_subdomain)
    '''Get the DMARC receiver record for a host.
    :param str host: The host to lookup.
    :param dnsfunc.  a function from domain names to txt records for DNS lookup
    :returns: The DMARC reciever record for the host.
    :rtype:  A dict of {tag => value} results

    The :func:`receiver_record` function looks up the DMARC reciever record
    for ``host``. If the host does not have a pubished record
    `the organizational domain`_ is determined. The DMARC record for the
    organizational domain is queried
    (if specified) or the overall record for the domain is returned.
    '''
    hostSansDmarc = host if host[:7] != '_dmarc.' else host[7:]

    retval = lookup_receiver_record(hostSansDmarc, dnsfunc)
    if retval:
        return (retval, False)

    # lookup for org_domain
    newHost = get_org_domain(host)
    retval = lookup_receiver_record(newHost, dnsfunc)

    return (retval, True)


def get_org_domain(domain):
    fn = get_suffix_list_file_name()
    with open(fn) as suffixList:
        psl = PublicSuffixList(suffixList)
        return psl.get_public_suffix(domain)


def get_suffix_list_file_name():
    # type: () -> Text
    '''Get the file name for the public-suffix list data file

    :returns: The filename for the datafile in this module.
    :rtype: ``str``'''
    # TODO: automatically update the suffix list data file
    # <https://publicsuffix.org/list/effective_tld_names.dat>

    if sys.version_info < (3, 0):
        try:
            from authheaders.findpsl import location
        except ImportError:
            location  = resource_filename('authheaders', 'public_suffix_list.txt')
    else:
        try:
            from authheaders.findpsl import location
        except ModuleNotFoundError:
            location  = resource_filename('authheaders', 'public_suffix_list.txt')
    return location
