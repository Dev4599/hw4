"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

ANSWER_CACHE = {}
ZONE_CACHE = {}


def _start_servers(target_name: dns.name.Name) -> list:
    """
    Find the best longest known zone covering target_name, falling back
    to the root servers when nothing closer is cached.
    """
    name = target_name
    while True:
        if name in ZONE_CACHE:
            return list(ZONE_CACHE[name])
        if name == dns.name.root:
            return list(ROOT_SERVERS)
        name = name.parent()


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    cache_key = (target_name, qtype)
    if cache_key in ANSWER_CACHE:
        return ANSWER_CACHE[cache_key]
    servers = _start_servers(target_name)
    outbound_query = dns.message.make_query(target_name, qtype)
    response = dns.message.make_response(outbound_query)
    while servers:
        next_servers = []
        answered = False
        for server in servers:
            try:
                server_response = dns.query.udp(outbound_query, server, 3)
            except Exception:
                continue
            if server_response.answer:
                cname_rrset = None
                for rrset in server_response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        cname_rrset = rrset
                        break
                if cname_rrset is not None:
                    chained = lookup(cname_rrset[0].target, qtype)
                    response = dns.message.make_response(outbound_query)
                    response.answer = [cname_rrset] + list(chained.answer)
                else:
                    response = server_response
                answered = True
                break
            zone_name = None
            ns_names = []
            for rrset in server_response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    zone_name = rrset.name
                    ns_names.extend(rr.target for rr in rrset)
            if not ns_names:
                continue
            for rrset in server_response.additional:
                if rrset.rdtype == dns.rdatatype.A and rrset.name in ns_names:
                    next_servers.extend(str(rr) for rr in rrset)
            if not next_servers:
                for ns_name in ns_names:
                    ns_response = lookup(ns_name, dns.rdatatype.A)
                    if any(rrset.rdtype == dns.rdatatype.CNAME
                           for rrset in ns_response.answer):
                        continue
                    for rrset in ns_response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            next_servers.extend(str(rr) for rr in rrset)
            if next_servers and zone_name is not None:
                ZONE_CACHE[zone_name] = next_servers
            break
        if answered:
            break
        servers = next_servers
    ANSWER_CACHE[cache_key] = response
    return response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()
