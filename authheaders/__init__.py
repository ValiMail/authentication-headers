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

import importlib.resources
import re
import sys
import copy
from email.utils import getaddresses
from authheaders.dmarc_lookup import dns_query, receiver_record, receiver_record_walk, get_org_domain
from authres import SPFAuthenticationResult, DKIMAuthenticationResult, AuthenticationResultsHeader
from authres.arc import ARCAuthenticationResult
from authres.dmarc import DMARCAuthenticationResult
from dkim import ARC, DKIM, arc_verify, dkim_verify, DKIMException, rfc822_parse
from dns.exception import DNSException

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


def get_domain_part(address):
    '''Return domain part of an email address'''
    if sys.version_info < (3, 0) and isinstance(address, str):
        address = bytes(address)
    elif isinstance(address, str):
        address = bytes(address, 'utf8')
    res = re.findall(b'@([a-z0-9.]+)', address, re.IGNORECASE)
    return res[0].lower().decode('ascii')


def check_psddmarc_list(psdname, dnsfunc=dns_query):
    """Check psddmarc.org list of PSD DMARC participants"""
    try:
        # If the PSD registry is locally available, use it.
        ref = importlib.resources.files('authheaders') / 'psddmarc.csv'
        with importlib.resources.as_file(ref) as psdfile_name:
            with open(psdfile_name) as psd_file:
                psds = []
                for line in psd_file.readlines():
                    sp = line.split(',')
                    if sp[1] == 'current':
                        psds.append(sp[0][1:])
                if psdname in psds:
                    return True
                else:
                    return False
    except:
        # If not, use the DNS query list.
        psd_list_host = '.psddmarc.org'
        psd_lookup = psdname + psd_list_host
        answer = dnsfunc(psd_lookup)
        if answer:
            return True
        else:
            return False


def dmarc_per_from(from_domain, spf_result=None, dkim_result=None, dnsfunc=None, psddmarc=False, dmarcbis=False, policy_only=False):
    """DMARC result for a single From domain."""
    original_from = from_domain
    psddomain = False
    if not dmarcbis: # It's all different in the future
        # Get dmarc record for domain
        if(dnsfunc):
            record, orgdomain = receiver_record(from_domain, dnsfunc=dnsfunc)
        else:
            record, orgdomain = receiver_record(from_domain)
        # Report if DMARC record is From Domain or Org Domain
        if record and orgdomain:
            result_comment = 'Used Org Domain Record'
            policydomain = orgdomain
        elif record:
            result_comment = 'Used From Domain Record'
            orgdomain = from_domain
            policydomain = None

        # Get psddmarc record if doing PSD DMARC, no DMARC record, and PSD is
        #  listed
        if (not record) and psddmarc:
            org_domain = get_org_domain(from_domain)
            if(dnsfunc):
                if check_psddmarc_list(org_domain.split('.',1)[-1],
                                       dnsfunc=dnsfunc):
                    record, _ = receiver_record(org_domain.split('.',1)[-1],
                                                dnsfunc=dnsfunc)
            else:
                if check_psddmarc_list(org_domain.split('.',1)[-1]):
                    record, _ = receiver_record(org_domain.split('.',1)[-1])
            if record:
                psddomain = org_domain.split('.',1)[-1]
                result_comment = 'Used Public Suffix Domain Record'
    else:
        # Get dmarc record for domain (tree walk)
        # TODO: Not very efficient.  Always does tree walk, even if not
        # really needed.  receiver_record_walk does sequential DNS lookups
        # vice parallel.
        orgdomain = False
        record = None
        if(dnsfunc):
            treeresults = receiver_record_walk(from_domain, dnsfunc=dnsfunc)
        else:
            treeresults = receiver_record_walk(from_domain)
        # Then find org domain, per DMARCbis 07
        # Fake psd=yes (since no one publishes this yet) - FIXME later
        for dmn, rec in reversed(list(treeresults.items())):
            if check_psddmarc_list(dmn):
                treeresults[dmn]['psd'] = 'y'
                break
        orgresults = copy.deepcopy(treeresults)
        psddomain = False
        for dmn, rec in list(treeresults.items()):
            try:
                psd = treeresults[dmn]['psd']
                # For psd=y, use next longer domain as org.
                if psd == 'y':
                    if dmn == from_domain:
                        orgdomain = dmn
                        record = rec
                        result_comment = 'Used From Domain which is also PSD'
                    else:
                        psddots = len(dmn[0].split('.'))
                        fromsplit = from_domain.split('.')
                        orgdomain = ''
                        start = True
                        for part in fromsplit[(len(fromsplit) - psddots - 1):]:
                            if not start:
                                orgdomain += '.'
                            start = False
                            orgdomain += part
                        try:
                            if treeresults[orgdomain]:
                                record = treeresults[orgdomain]
                        except:
                            record = rec
                            psddomain = dmn
                        result_comment = 'Used Tree Walk, org one level below PSD'
                    break
                # For psd=n, this is the org domain.
                if psd == 'n':
                    orgdomain = dmn
                    record = rec
                    result_comment = 'Used Tree Walk Record which is PSD=n'
                    break
            except:
                # No PSD tag
                pass
        if not orgdomain:
            # If psd=u (implicit or explicit), usual case.
            for dmn, rec in reversed(list(treeresults.items())):
                if rec and dmn != from_domain:
                    orgdomain = dmn
                    record = rec
                    result_comment = 'Used Tree Walk Record'
                    break
        if not orgdomain:
            # If all else fails, the From domain is the org domain.
            orgdomain = from_domain
            try:
                record = treeresults[from_domain]
                result_comment = 'Used From Domain Record'
            except:
                record = False
                result_comment = 'From domain has no DMARC record'


    if record and record.get('p'): # DMARC P tag is mandatory
        # find policy
        policy = record['p']
        if policy[-1:] == '\\':
            policy = policy[:-1]
        try:
            sp = record['sp']
            if sp[-1:] == '\\':
                sp = sp[:-1]
        except KeyError:
            sp = policy
        try:
            np = record['np']
            if np[-1:] == '\\':
                np = np[:-1]
        except KeyError:
            np = None

        if orgdomain or psddomain:
            if np:
                exists = False
                for qtype in ['a', 'mx', 'aaaa']:
                    if(dnsfunc):
                        res = dnsfunc(from_domain)
                    else:
                        res = dns_query(from_domain, qtype)
                    if res:
                        exists = True
                        break
                if exists:
                    policy = sp
                else:
                    policy = np
            else:
                policy = sp

        adkim = record.get('adkim', 'r')
        aspf  = record.get('aspf',  'r')

        # get result
        result = "fail"
        if not policy_only and spf_result and spf_result.result == "pass":
            # The domain in SPF results often includes the local part, even though
            # generally it SHOULD NOT (RFC 7601, Section 2.7.2, last paragraph).
            try:
                mail_from_domain = get_domain_part(spf_result.smtp_mailfrom)
            except IndexError:
                mail_from_domain = None
            spf_result.smtp_mailfrom = mail_from_domain
            if aspf == "s" and from_domain == mail_from_domain:
                result = "pass"
            elif aspf == "r" and get_org_domain(from_domain) == get_org_domain(mail_from_domain):
                result = "pass"

        if not policy_only and dkim_result and dkim_result.result == "pass":
            if adkim == "s" and from_domain == dkim_result.header_d:
                result = "pass"
            elif adkim == "r" and get_org_domain(from_domain) == get_org_domain(dkim_result.header_d):
                result = "pass"
    else:
        # If no DMARC record, no result
        result = 'none'
        result_comment = ''
        from_domain = ''
        policy = ''

    if policy_only:
        if psddomain:
            policydomain = psddomain
        else:
            policydomain = orgdomain
        if not record:
            result_comment = "None"
            policydomain = None
        results = [original_from, policydomain, result_comment, policy, record, orgdomain]
        return(results)
    else:
        return(result, result_comment, from_domain, policy)

def check_spf(ip, mail_from, helo):
    res, reason = spf.check2(ip, mail_from, helo)
    if res is not None:
        return SPFAuthenticationResult(result=res, reason=reason, smtp_mailfrom=mail_from, smtp_helo=helo)
    else:
        return SPFAuthenticationResult(result=None, reason=None, smtp_mailfrom=mail_from, smtp_helo=helo)


def check_dkim(msg, dnsfunc=None):
    try:
        d = DKIM(msg)
        if(dnsfunc):
            res = d.verify(dnsfunc=dnsfunc) and 'pass' or 'fail'
        else:
            res = d.verify() and 'pass' or 'fail'
    except DKIMException as e:
        res = 'fail'
    except DNSException as e:
        res = 'temperror'
    except Exception as e:
        res = 'fail'

    header_i = d.signature_fields.get(b'i', b'').decode('ascii')
    header_d = d.signature_fields.get(b'd', b'').decode('ascii')
    if res:
        return DKIMAuthenticationResult(result=res, header_d=header_d, header_i=header_i)
    else:
        return DKIMAuthenticationResult(result=None)


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
    except DNSException as e:
        cv, results, comment = CV_Fail, [], "%s" % e
    except Exception as e:
        cv, results, comment = CV_Fail, [], "%s" % e
    if comment == 'success':
        comment = None
    if cv is not None:
        return ARCAuthenticationResult(result=cv.decode('ascii'), result_comment=comment)
    else:
        return ARCAuthenticationResult(result='none', result_comment=comment)


def check_dmarc(msg, spf_result=None, dkim_result=None, dnsfunc=None, psddmarc=False, dmarcbis=False):

    # get from domain
    headers, _ = rfc822_parse(msg)
    from_headers = [a[1] for a in getaddresses(x[1].replace(b'\r\n', b'')
        .decode(errors='ignore').strip() for x in headers
        if x[0].lower() == b"from")]

    if len(from_headers) > 1:
        # multi-from processing per RFC 7489 6.6.1
        domain_results = []
        for from_header in from_headers:
            try:
                from_domain = get_domain_part(from_header)
            except IndexError:
                result = 'permerror'
                result_comment = 'Unable to extract From domain: {0}'.format(from_header)
                return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from='none', policy='none')
            try:
                domain_results.append(dmarc_per_from(from_domain, spf_result=spf_result, dkim_result=dkim_result, dnsfunc=dnsfunc, psddmarc=psddmarc, dmarcbis=dmarcbis))
            except dmarc_lookup.DMARCException as result_comment:
                result = 'permerror'
                return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy='none')

        for domain in domain_results:
            if domain[3] == 'reject':
                result, result_comment, from_domain, policy = domain
                return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy=policy)
        for domain in domain_results:
            if domain[3] == 'quarantine':
                result, result_comment, from_domain, policy = domain
                return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy=policy)
        for domain in domain_results:
            if domain[3] == 'none':
                result, result_comment, from_domain, policy = domain
                return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy=policy)
        result, result_comment, from_domain, policy = domain
    elif len(from_headers) == 1:
        from_header =  from_headers[0]
        try:
            from_domain = get_domain_part(from_header)
        except IndexError:
            result = 'permerror'
            result_comment = 'Unable to extract From domain: {0}'.format(from_header)
            return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from='none', policy='none')
        try:
            result, result_comment, from_domain, policy = dmarc_per_from(from_domain, spf_result=spf_result, dkim_result=dkim_result, dnsfunc=dnsfunc, psddmarc=psddmarc, dmarcbis=dmarcbis)
        except dmarc_lookup.DMARCException as result_comment:
            result = 'permerror'
            return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy='none')

    else:
        result = 'none'

    if result != 'none':
        return DMARCAuthenticationResult(result=result, result_comment=result_comment, header_from=from_domain, policy=policy)
    else:
        return DMARCAuthenticationResult(result=result, header_from=from_domain)


def authenticate_message(msg, authserv_id, prev=None, spf=False, dkim=True, arc=False, dmarc=True, ip=None, mail_from=None, helo=None, dnsfunc=None, psddmarc=False, dmarcbis=False):
    """Authenticate an RFC822 message and return the Authentication-Results header
    @param msg: an RFC822 formatted message (with either \\n or \\r\\n line endings)
    @param authserv_id: The id of the server performing the authentication
    @param prev: an existing authentication results header to append results to
    @param spf: Perform SPF check
    @param dkim: Perform DKIM check
    @param dmarc: Perform DMARC check
    @param psddmarc: Perform PSD DMARC check (RFC 9091)
    @param dmarcbis: Use DMARCbis policy discovery and alignment
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
        dmarc_result = check_dmarc(msg, spf_result, dkim_result, dnsfunc=dnsfunc, psddmarc=psddmarc, dmarcbis=dmarcbis)
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
    @param timestamp: (for ARC testing) a manual timestamp to use for ARC signature generation
    @param logger: An optional logger
    @param standardize: A testing flag for arc to output a standardized header format
    @return: The DKIM-Message-Signature, or ARC set headers
    @raises: DKIMException if mis-configured
    """

    if sig=="DKIM":
        return DKIM(msg, logger=logger).sign(selector, domain, privkey, include_headers=sig_headers,
                              identity=identity, length=length, canonicalize=canonicalize)
    else:
        return ARC(msg, logger=logger).sign(selector, domain, privkey, srv_id, include_headers=sig_headers, timestamp=timestamp, standardize=standardize)
