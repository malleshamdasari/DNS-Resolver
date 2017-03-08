from __future__ import print_function

import sys
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

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

if len(sys.argv) < 3:
    print("please provide the domain and record type")
    exit()
dname = sys.argv[1]
rdtype = sys.argv[2]
qname = dns.name.from_text(dname)
labels = qname.labels
itrs = len(labels)
timeout_flag = 1
sp = 0

def verify_hash(next_ns, name, curr_ns):
    ds_q = dns.message.make_query(name, 43, want_dnssec=True)
    ds_r = dns.query.tcp(ds_q, curr_ns, timeout=1)
    k_q = dns.message.make_query(name, 48, want_dnssec=True)
    k_r = dns.query.tcp(k_q, next_ns, timeout=1)

    if len(k_r.answer) == 0:
        print("dnssec is not supported")
        return 0
    KSK = None
    keys = k_r.answer[0].items
    for item in keys:
        if item.flags == 257:
            KSK = item
    if KSK == None:
        print("No KSK")
        return 0
    ds_items = ds_r.answer[0].items
    alg=0
    if len(ds_items)==0:
        print("No DS record")
    else:
        if ds_items[0].digest_type == 1:
            alg='SHA1'
        elif ds_items[0].digest_type==2:
            alg='SHA256'
    new_ds = dns.dnssec.make_ds(name, KSK, alg)
    if new_ds.digest != ds_items[0].digest:
        print("DS is not matched.")
        return False
    return True

def dig_query(name, rdclass, rdtype, nameservers, tflag):
    global itrs
    global timeout_flag
    global sp
    qname = dns.name.from_text(name)
    labels = qname.labels
    for ns in nameservers:
        ns = str(ns)
        try: 
            kname = None
            if timeout_flag and sp < itrs+1:
                sp += 1
            timeout_flag = 1
            if sp < itrs+1:
                kname = str(qname.split(sp)[1])
            if kname is not None:
                jname = dns.name.from_text(kname)
                qrec = dns.message.make_query(qname, rdtype, want_dnssec=True)
                rrec = dns.query.tcp(qrec, ns, timeout=1)
                qsec = dns.message.make_query(jname, 48, want_dnssec=True)
                rsec = dns.query.tcp(qsec, ns, timeout=1)
                zsk = None
                print(rrec)
                if len(rsec.answer) > 0:
                    zsk = rsec.answer[0]
                    try:
                        ## Verify the DNS Keys ##
                        dns.dnssec.validate(rsec.answer[0], rsec.answer[1], {jname:zsk})
                    except:
                    	print("DNSSEC is configured but failed here")
                        return 1, None
                if len(rrec.answer) > 0 and len(rsec.answer) > 0:
                    zsk = rsec.answer[0]
                    try:
                        ## Verify the RRsig from answer ##
                        dns.dnssec.validate(rrec.answer[0], rrec.answer[1], {jname:zsk})
                    except:
                    	print("DNSSEC is configured but failed here")
                        return 1, None
                elif len(rrec.authority) > 0 and len(rsec.answer) > 0:
                    zsk = rsec.answer[0]
                    try:
                        ## Verify the RRsig from authority ##
                        dns.dnssec.validate(rrec.authority[1], rrec.authority[2], {jname:zsk})
                    except:
                    	print("DNSSEC is configured but failed here")
                        return 1, None
                else:
                    print("DNSSEC is not supported")
                    return 1, None
            q = dns.message.make_query(qname, rdtype)
            r = dns.query.tcp(q, ns, timeout=1)
            root = 0
            if r.rcode() != dns.rcode.NOERROR:
                print("ERROR")
                continue
            elif len(r.answer) > 0:
                for ans in r.answer:
                    if (ans.rdtype == 1 or ans.rdtype == 2 or ans.rdtype == 15):
                        return 1, r
                    if (rdtype != "A" and ans.rdtype == 5):
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
                            result = verify_hash(item.address, r.authority[0].name, ns)
                            if not result:
                                return 1, None
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
                    if done and r is not None:
                        for ans in r.answer:
                            for item in ans.items:
                                ip.append(str(item))
                done, r = dig_query(name, rdclass, rdtype, ip, 1)
                if done:
                    return 1, r
        except dns.rdatatype.UnknownRdatatype:
            print ("Unknown Rdatatype\n")
        except dns.rdataclass.UnknownRdataclass:
            print ("Unknown Rdataclass\n")
        except dns.exception.SyntaxError:
            print ("Malformed\n")
        except dns.exception.Timeout:
            print ("Timeout\n")
            timeout_flag = 0
    return None, None
	
done, r = dig_query(dname, "IN", "A", rootservers, 1)
if r is not None:
    print("DNSSEC is configured and validated here")
    print(r)
