from __future__ import print_function

import sys
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time

rootservers = ['198.41.0.4',
               '192.228.79.201',
               '192.33.4.12',
               '199.7.91.13',
               '192.203.230.10',
               '192.5.5.241',
               '192.112.36.4',
               '198.97.190.53',
               '192.36.148.17',
               '192.58.128.30',
               '193.0.14.129',
               '199.7.83.42',
               '202.12.27.33']

#rootservers = ['8.8.8.8', '8.8.4.4']

def dig_query(name, rdclass, rdtype, nameservers, tflag):
    qname = dns.name.from_text(name)
    for ns in nameservers:
        ns = str(ns)
        try:
            q = dns.message.make_query(qname, rdtype)
            r = dns.query.udp(q, ns, timeout=1)
            if r.rcode() != dns.rcode.NOERROR:
                continue
            elif len(r.answer) > 0:
                for ans in r.answer:
                    if (ans.rdtype == 1 or ans.rdtype == 2 or ans.rdtype == 15):
                        return 1, r
                    elif (rdtype != "A" and ans.rdtype == 5):
                        return 1, r
                for ans in r.answer:
                    if (ans.rdtype == 5):
                        cname = str(ans.items[0].target)
                        done, r = dig_query(cname, rdclass, rdtype, rootservers, 1)
                        if done:
                            return 1, r
            elif len(r.additional) > 0:
                nslist = []
                for x in r.additional:
                    if x.rdtype == 1:
                        for item in x.items:
                            nslist.append(str(item))
                done, r = dig_query(name, rdclass, rdtype, nslist, 1)
                if done:
                    return 1, r
            elif len(r.authority) > 0:
                nslist = []
                for x in r.authority:
                    for item in x.items:
                        nslist.append(str(item))
                ip = []
                for ns in nslist:
                    done, r = dig_query(ns, rdclass, "A", rootservers, 1)
                    if done:
                        for ans in r.answer:
                            for item in ans.items:
                                ip.append(str(item))
                done, r = dig_query(name, rdclass, rdtype, ip, 1)
                if done:
                    return 1, r
        except dns.rdatatype.UnknownRdatatype:
            print("Unknown Rdatatype\n")
        except dns.rdataclass.UnknownRdataclass:
            print("Unknown Rdataclass\n")
        except dns.exception.SyntaxError:
            print("Malformed\n")
        except dns.exception.Timeout:
            print("Timeout\n")
    return None, None

if len(sys.argv) < 3:
    print("please provide the domain and record type")
    exit()
dname = sys.argv[1]
rdtype = sys.argv[2]
done, r = dig_query(dname, "IN", rdtype, rootservers, 1)
if r is not None:
    print(r)
