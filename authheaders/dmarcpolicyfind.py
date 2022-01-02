#!/usr/bin/python3


import argparse



def main():
    """ Find DMARC policy for a domain.

    There are up to three different conventions for DMARC related policy
    discovery:
        1.  RFC 7489: domain + org domain
        2.  RFC 9091: domain + ord domain + PSD domain
        3.  dmarcbis-04 [1]: domain + walk

    This script checks to see which policy is relevant to a domain based on
    these     methods.
    @param domain: Policy domain to locate.
    @param s: Policy selection logic to use, default DMARC.
    @param v: Verbose output

    [1] https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis Section 4.5
        DNS Tree Walk
    """
    parser = argparse.ArgumentParser(
        description='Find DMARC policy for a domain.',)
    parser.add_argument('domain', action="store",
                        help='Usually From: domain of an email')
    parser.add_argument('-s', '--select',
                        choices=['DMARC', 'PSD', 'DMARCbis'], default='DMARC',
                        help='Select policy discovery method: Default is \
                        DMARC, use multiple -s invocations for multiple \
                        methods')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='turn verbose mode on')
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
                        help='turn quiet mode on.  Exit 0 == policy found.  \
                        Exit 1 == no policy found.')
    args=parser.parse_args()
    args.domain = bytes(args.domain, encoding='UTF-8')
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()


if __name__ == '__main__':
  main()

