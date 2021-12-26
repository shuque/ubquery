#!/usr/bin/env python3
#

"""
pyub.py

"""

import os
import sys
import argparse
import unbound
import dns.rcode
import dns.rdata
import dns.rdatatype
import dns.message


__version__ = "0.0.1"
__progname__ = os.path.basename(sys.argv[0])

# List of DNSSEC trust anchors (this is the current root KSK)
# pylint: disable=line-too-long
__trust_anchor_list__ = [
    ". DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3 +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF 0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN R1AkUTV74bU="
]

# Local resolver configuration file
__resolv_conf__ = "/etc/resolv.conf"


def process_arguments():
    """Process command line arguments"""

    parser = argparse.ArgumentParser(
        description='Validating DNS query program using libunbound.')
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase output verbosity")
    parser.add_argument("qname",
                        help="DNS query name")
    parser.add_argument("qtype",
                        help="DNS query type")
    return parser.parse_args()


class Result:
    """Result class"""

    def __init__(self, ctx, qname, qtype):
        self.qname = qname
        self.qtype = qtype
        self.rcode = None
        self.secure = False
        self.ttl = None
        self.answers = []
        self.answers_raw = []
        self.message = None
        self.get_response(ctx)

    def get_response(self, ctx):
        """get response to query"""
        status, result = ctx.resolve(self.qname,
                                     dns.rdatatype.from_text(self.qtype),
                                     unbound.RR_CLASS_IN)
        if status != 0:
            raise RuntimeError(f'unbound resolve returned status={status}')
        self.rcode = result.rcode
        self.secure = result.secure == 1
        self.ttl = result.ttl
        self.message = dns.message.from_wire(result.packet)
        if result.data:
            self.answers_raw = result.data.data
            for item in self.answers_raw:
                rdata = dns.rdata.from_wire(1, self.qtype, item, 0, len(item))
                self.answers.append(rdata)

    def __str__(self):
        return f'Result: {self.qname} {self.qtype}'


def init_context():
    """initialize unbound context"""

    ctx = unbound.ub_ctx()
    ctx.resolvconf(__resolv_conf__)
    for trust_anchor in __trust_anchor_list__:
        ctx.add_ta(trust_anchor)
    return ctx


def print_result(result, verbose):
    """Print result information"""

    print(f'RCODE: {dns.rcode.to_text(result.rcode)}')
    print(f'SECURE: {result.secure}')
    print(f'TTL: {result.ttl}')
    print('')
    print(f'ANSWERS: count={len(result.answers)}')
    for item in result.answers:
        print(item)

    if verbose:
        print('\nFULL RESPONSE PACKET:')
        print(result.message)


def main(arguments):
    """main function"""

    ctx = init_context()
    result = Result(ctx, arguments.qname, arguments.qtype)
    print_result(result, arguments.verbose)


if __name__ == '__main__':

    args = process_arguments()
    main(args)
