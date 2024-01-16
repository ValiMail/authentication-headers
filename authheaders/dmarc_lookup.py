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
import importlib.resources
try:
    # typing is needed by mypy, but is unused otherwise
    from typing import Dict, Text  # noqa: F401
except ImportError:
    pass
from dns.resolver import (resolve, NXDOMAIN, NoAnswer, NoNameservers)
try:
    from publicsuffix2 import PublicSuffixList
except ImportError:
    # Fall back to deprecated publicsuffix if publicsuffix2 is not available
    from publicsuffix import PublicSuffixList
import sys
from collections import OrderedDict

class DMARCException(Exception):
    """Base class for DMARC errors."""
    pass

def answer_to_dict(answer):
    # type: (Text) -> Dict[unicode, unicode]
    '''Turn the DNS DMARC answer into a dict of tag:value pairs.
    Examples:
    >>> answer_to_dict("v=DMARC1; p=reject; rua=mailto:dmarc.reports@valimail.com,mailto:dmarc_agg@vali.email; ruf=mailto:dmarc.reports@valimail.com,mailto:dmarc_c0cb7153_afrf@vali.email")
    {'v': 'DMARC1', 'p': 'reject', 'rua': 'mailto:dmarc.reports@valimail.com,mailto:dmarc_agg@vali.email', 'ruf': 'mailto:dmarc.reports@valimail.com,mailto:dmarc_c0cb7153_afrf@vali.email'}
    >>> answer_to_dict("v=DMARC1; p=none; sp=reject")
    {'v': 'DMARC1', 'p': 'none', 'sp': 'reject'}
    >>> answer_to_dict('"v=DMARC1; p=none; rua=mailto:dmarc.wheaton.rua@wheaton.edu,mailto:dmarc_agg@waybettermarketing.com; ruf=mailto:dmarc.wheaton.ruf@wheaton.edu,mailto:dmarc_fr@waybettermarketing.com; fo=1;" ""')
    {'v': 'DMARC1', 'p': 'none', 'rua': 'mailto:dmarc.wheaton.rua@wheaton.edu,mailto:dmarc_agg@waybettermarketing.com', 'ruf': 'mailto:dmarc.wheaton.ruf@wheaton.edu,mailto:dmarc_fr@waybettermarketing.com', 'fo': '1'}
    >>> try:
    ...     answer_to_dict("v=DMARC1;p=none;pct=100;rua=mailto:postmaster@somenet.org;mailto:postmaster@somenet.org;ri=3600;fo=1;")
    ... except DMARCException as a:
    ...     print('dmarc_lookup.DMARCException:', a)
    dmarc_lookup.DMARCException: missing tag or value: v=DMARC1;p=none;pct=100;rua=mailto:postmaster@somenet.org;mailto:postmaster@somenet.org;ri=3600;fo=1;
    '''

    a = answer.strip('" ')
    rawTags = [t.split('=') for t in a.split(';') if t]
    try:
        retval = {t[0].strip().lower(): t[1].strip().lower() for t in rawTags}
    except IndexError:
        raise DMARCException('missing tag or value: {0}'.format(answer))
    # Simpler to lowercase everything and put 'v' back.  Already validated
    # before answer_to_dict is called, so should be fine.
    retval['v'] = 'DMARC1'
    return retval

def dns_query(name, qtype='TXT'):
    try:
        return resolve(name, qtype)
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
    # like the dns.resolver object).
    if dnsfunc != dns_query:
        if answer:
            answer = ['"' + answer + '"']

    if not answer:
        return {}
    else:
        # One might think the only TXT record at _dmarc would be a DMARC
        # record, but one would be wrong.  We need to check all the answers,
        # not just the first.  Also, we can addrss RFC 7489, Section 6.6.3,
        # Policy Discovery reuls to treat two DMARC records like none.
        tags = False
        for result in answer:
            # Check that v= field is the first one in the answer (which is in
            # double quotes) as per Section 7.1 (5):
            #     In particular, the "v=DMARC1" tag is mandatory and MUST appear
            #     first in the list. Discard any that do not pass this test.
            # http://tools.ietf.org/html/draft-kucherawy-dmarc-base-04#section-7.1
            if str(result)[:9] == '"v=DMARC1':
                if not tags:
                    tags = answer_to_dict(str(result))
                else:
                    return {} # Multiple DMARC records
        if tags:
            return tags # One DMARC record worth of tags
        else:
            return {} # No DMARC records


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

    return (retval, newHost)

def receiver_record_walk(host, dnsfunc=dns_query):
    # type: (str), dnsfunc(optional) -> (Dict[unicode, unicode])
    '''Get the DMARC receiver record for a host using the DMARCbis-07 tree
    walk.
    :param str host: The host to lookup.
    :param dnsfunc.  a function from domain names to txt records for DNS lookup
    :returns: The DMARC reciever record for the host.
    :rtype:  A dict of {tag => value} results

    The :func:`receiver_record_walk` function looks up the DMARC reciever
    record for ``host``. If the host does not have a pubished record, the DNS
    tree is walked up until a record is found or the tree is exhausted.
    Specific types of lookups such as organizational domain or PSD are no
    longer relevant.

    If multiple records are returned, the first (longest match) is the policy
    record.  The last, non-PSD (no psd=y flag) is the organizational domain
    for alignment determination.

    Return a list of results for each step in the tree walk.
    '''
    hostSansDmarc = host if host[:7] != '_dmarc.' else host[7:]

    result = OrderedDict()
    retval = lookup_receiver_record(hostSansDmarc, dnsfunc)
    if retval:
        result[hostSansDmarc] = retval

    # walk the tree
    tree = hostSansDmarc.split('.')
    if len(tree) < 5:
        level = len(tree) - 1
    else:
        level = 4
    while level > 0:
        newHost = '.'.join(tree[(len(tree) - level):len(tree)])
        level -= 1
        retval = lookup_receiver_record(newHost, dnsfunc)
        if retval:
            result[newHost] = retval
    return result


def get_org_domain_from_suffix_list(location, domain):
    with open(location) as suffixList:
        psl = PublicSuffixList(suffixList)
        return psl.get_public_suffix(domain)


def get_org_domain(domain):
    try:
        from authheaders.findpsl import location
        return get_org_domain_from_suffix_list(location, domain)
    except ModuleNotFoundError:
        ref = importlib.resources.files('authheaders') / 'public_suffix_list.txt'
        with importlib.resources.as_file(ref) as location:
            return get_org_domain_from_suffix_list(location, domain)

def _test():
    import doctest, dmarc_lookup
    return doctest.testmod(dmarc_lookup)


if __name__ == '__main__':
    _test()
