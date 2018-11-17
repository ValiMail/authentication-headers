# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2017 Valimail Inc
# Contact: Gene Shuman <gene@valimail.com>
#

import re
from authheaders.dmarc_lookup import receiver_record, get_org_domain
from authres import SPFAuthenticationResult, DKIMAuthenticationResult, AuthenticationResultsHeader
from authres.arc import ARCAuthenticationResult
from authres.dmarc import DMARCAuthenticationResult
from dkim import ARC, DKIM, arc_verify, dkim_verify, DKIMException, rfc822_parse

# Please accept my appologies for doing this
try:
    import spf
except ImportError:
    pass

__all__ = [
    "authenticate_message",
    "sign_message",
    "chain_validation"
    ]


def check_spf(ip, mail_from, helo):
    res, _, reason = spf.check(ip, mail_from, helo)
    return SPFAuthenticationResult(result=res, reason=reason, smtp_mailfrom=mail_from, smtp_helo=helo)


def check_dkim(msg, dnsfunc=None):
    d = DKIM(msg)
    try:
        if(dnsfunc):
            res = d.verify(dnsfunc=dnsfunc) and 'pass' or 'fail'
        else:
            res = d.verify() and 'pass' or 'fail'
    except DKIMException as e:
        res = 'fail'

    header_i = d.signature_fields.get(b'i', b'').decode('ascii')
    header_d = d.signature_fields.get(b'd', b'').decode('ascii')

    return DKIMAuthenticationResult(result=res, header_d=header_d, header_i=header_i)


def check_arc(msg, logger=None, dnsfunc=None):
    """ Compute the chain validation status of an inbound message.
    @param msg: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param logger: An optional logger
    @param dnsfunc: An optional dns lookup function (intended for testing)
    """

    a = ARC(msg)
    try:
        if(dnsfunc):
            cv, results, comment = a.verify(dnsfunc=dnsfunc)
        else:
            cv, results, comment = a.verify()
    except DKIMException as e:
        cv, results, comment = CV_Fail, [], "%s" % e

    return ARCAuthenticationResult(result=cv.decode('ascii'))


def check_dmarc(msg, spf_result=None, dkim_result=None, dnsfunc=None):
    # get from domain
    headers, _ = rfc822_parse(msg)
    from_headers = [x[1] for x in headers if x[0].lower() == b"from"]
    if len(from_headers) != 1:
        raise Exception("")
    from_header = from_headers[0]

    # kind of janky
    res = re.search(b'@(.*)>', from_header)
    from_domain = res.group(1).decode('ascii')

    # get dmarc record
    if(dnsfunc):
        record, _ = receiver_record(from_domain, dnsfunc=dnsfunc)
    else:
        record, _ = receiver_record(from_domain)

    adkim = record.get('adkim', 'r')
    aspf  = record.get('aspf',  'r')

    # get result
    result = "fail"
    if spf_result and spf_result.result == "pass":
        if aspf == "s" and from_domain == spf_result.smtp_mailfrom:
            result = "pass"
        elif aspf == "r" and get_org_domain(from_domain) == get_org_domain(spf_result.smtp_mailfrom):
            result = "pass"

    if dkim_result and dkim_result.result == "pass":
        if adkim == "s" and from_domain == dkim_result.header_d:
            result = "pass"
        elif adkim == "r" and get_org_domain(from_domain) == get_org_domain(dkim_result.header_d):
            result = "pass"

    return DMARCAuthenticationResult(result=result, header_from=from_domain)


def authenticate_message(msg, authserv_id, prev=None, spf=True, dkim=True, arc=False, dmarc=True, ip=None, mail_from=None, helo=None, dnsfunc=None):
    """Authenticate an RFC822 message and return the Authentication-Results header
    @param msg: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param authserv_id: The id of the server performing the authentication
    @param prev: an existing authentication results header to append results to
    @param spf: Perform SPF check
    @param dkim: Perform DKIM check
    @param dmarc: Perform DMARC check
    @param arc: Perform ARC chain validation check
    @param ip: (SPF) IP address of incoming request
    @param mail_from: (SPF) Sender declared in MAIL FROM
    @param helo: (SPF) EHLO/HELO domain of incoming message
    @param dnsfunc: An optional dns lookup function (intended for testing)
    @return: The Authentication-Results header
    """

    if spf and 'spf' not in sys.modules:
        raise Exception('pyspf must be installed manually for spf authentication')

    results = []
    if prev:
        arobj = AuthenticationResultsHeader.parse(prev)
        results = arobj.results

    spf_result  = next((x for x in results if type(x) == SPFAuthenticationResult), None)
    dkim_result = next((x for x in results if type(x) == DKIMAuthenticationResult), None)
    arc_result  = next((x for x in results if type(x) == ARCAuthenticationResult), None)

    if spf and not spf_result:
        spf_result = check_spf(ip, mail_from, helo)
        results.append(spf_result)

    if dkim and not dkim_result:
        dkim_result = check_dkim(msg, dnsfunc=dnsfunc)
        results.append(dkim_result)

    if arc and not arc_result:
        arc_result = check_arc(msg, None, dnsfunc=dnsfunc)
        results.append(arc_result)

    if dmarc:
        dmarc_result = check_dmarc(msg, spf_result, dkim_result, dnsfunc=dnsfunc)
        results.append(dmarc_result)

    auth_res = AuthenticationResultsHeader(authserv_id=authserv_id, results=results)
    return str(auth_res)

def sign_message(msg, selector, domain, privkey, sig_headers, sig='DKIM', srv_id=None,
                 identity=None, length=None, canonicalize=(b'relaxed', b'relaxed'), timestamp=None,
                 logger=None, standardize=False):
    """Sign an RFC822 message and return the ARC or DKIM header(s)
    @param msg: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param selector: the DKIM selector value for the signature
    @param domain: the DKIM domain value for the signature
    @param privkey: a PKCS#1 private key in base64-encoded text form
    @param sig_headers: a list of strings indicating which headers are to be signed
    @param sig: "DKIM" or "ARC"
    @param srv_id: an authserv_id to identify AR headers to sign
    @param identity: (DKIM) the DKIM identity value for the signature (default "@"+domain)
    @param length: (DKIM) true if the l= tag should be included to indicate body length (default False)
    @param canonicalize: (DKIM) the canonicalization algorithms to use (default (Relaxed, Relaxed))
    @param timestamp: (for testing) a manual timestamp to use for signature generation
    @param logger: An optional logger
    @param standardize: A testing flag for arc to output a standardized header format
    @return: The DKIM-Message-Signature, or ARC set headers
    @raises: DKIMException if mis-configured
    """

    if sig=="DKIM":
        return DKIM(msg, logger=logger).sign(selector, domain, privkey, include_headers=sig_headers,
                              identity=identity, length=length, canonicalize=canonicalize, timestamp=timestamp)
    else:
        return ARC(msg, logger=logger).sign(selector, domain, privkey, srv_id, include_headers=sig_headers, timestamp=timestamp, standardize=standardize)
