#!/usr/bin/python -tt

# cisco-ios-audit parses a Cisco IOS configuration file and generates a report 
# to efficiently perform an IT Security Audit
# Copyright: (c) 2015 Jonar M.
# License: BSD, see LICENSE for more details.

from ciscoconfparse import CiscoConfParse
import sys

#Accepts input using command line arguments 
dname = str(sys.argv[1])
parse = CiscoConfParse(dname)

print '---------start----------'
print dname
print '-------------------'
print 'Global Config Audit'
print '-------------------'
#Requirement - Enabled
#vtp mode
if parse.find_lines('^vtp\smode\stransparent') or parse.find_lines('^vtp\smode\soff'):
    print 'vtp mode = PASS'
else:
    print 'vtp mode = FAIL'

#service password-encryption
if parse.find_lines('^service\spassword-encryption'):
    print 'service password-encryption = PASS'
else:
    print 'service password-encryption = FAIL'

#ip source-route
if parse.find_lines('^no\sip\ssource-route'):
    print 'no ip source-route = PASS'
else:
    print 'no ip source-route = FAIL'

#domain lookup
if parse.find_lines('^no\sip\sdomain-lookup') or parse.find_lines('^no\sip\sdomain\slookup'):
    print 'no ip domain lookup = PASS'
else:
    print 'no ip domain lookup = FAIL'

#enable secret
if parse.find_lines('^enable\ssecret'):
    print 'enable secret = PASS'
else:
    print 'enable secret = FAIL'

#banner motd
if parse.find_lines('^banner\smotd'):
    print 'banner motd = PASS'
else: 
    print 'banner motd = FAIL'

#aaa authentication attempts login 5
if parse.find_lines('^aaa\sauthentication\sattempts\slogin\s5'):
    print 'aaa authentication attempts login 5 = PASS'
else:
    print 'aaa authentication attempts login 5 = FAIL'

#aaa authentication enable default group tacacs+ enable
if parse.find_lines('^aaa\sauthentication\senable\sdefault\sgroup\stacacs\+\senable') or parse.find_lines('^aaa\sauthentication\senable\sdefault\sgroup\stacacs\+\sline\senable'):
    print 'aaa authentication enable default group tacacs+ enable = PASS'
else:
    print 'aaa authentication enable default group tacacs+ enable = FAIL'

#aaa authorization exec default group tacacs+ if-authenticated
if parse.find_lines('^aaa\sauthorization\sexec\sdefault\sgroup\stacacs\+\sif-authenticated'):
    print 'aaa authorization exec default group tacacs+ if-authenticated = PASS'
else:
    print 'aaa authorization exec default group tacacs+ if-authenticated = FAIL'

#Requirement - Disabled
#udp-small-servers
if parse.find_lines('^service\sudp-small-servers'):
    print 'no service udp-small-servers = FAIL'
else:
    print 'no service udp-small-servers = PASS'

#tcp-small-servers
if parse.find_lines('^service\stcp-small-servers'):
    print 'no service tcp-small-servers = FAIL'
else:
    print 'no service tcp-small-servers = PASS'

#ip finger
if parse.find_lines('^ip\sfinger'):
    print 'no ip finger = FAIL'
else:
    print 'no ip finger = PASS'

#ip http server
if parse.find_lines('^ip\shttp\sserver'):
    print 'no ip http server = FAIL'
else:
    print 'no ip http server = PASS'

#ip bootp server 
if parse.find_lines('^ip\sbootp\sserver'):
    print 'no ip bootp server = FAIL'
else:
    print 'no ip bootp server = PASS'

#boot network
if parse.find_lines('^boot\snetwork'):
    print 'no boot network = FAIL'
else:
    print 'no boot network = PASS'

#service config
if parse.find_lines('^service\sconfig'):
    print 'no service config = FAIL'
else:
    print 'no service config = PASS'

#If not in use, disable. If in use, restrictions must apply
#snmp
if parse.find_lines('^snmp-server\sgroup\sprivate') or parse.find_lines('^snmp-server\sgroup\spublic') or parse.find_lines('^snmp-server\scommunity\sprivate') or parse.find_lines('^snmp-server\scommunity\spublic'):
    print 'snmp = FAIL'
else:
    print 'snmp = PASS'

#logging
if parse.find_lines('^logging\s\d') or parse.find_lines('^logging\shost\s\d'):
    print 'logging = PASS'
else:
    print 'logging = FAIL'

#ntp
if parse.find_lines('^ntp\sserver\s\d'):
    print 'ntp = PASS'
else:
    print 'ntp = FAIL'


print '----------------------'
print 'Interface Config Audit'
print '----------------------'
#switchport port-security
ps_intfs_total = 0
ps_intfs_success = 0
ps_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sswitchport\smode\saccess')
for ps_obj in ps_intfs:
    if not ps_obj.re_search_children(r'^\sswitchport\sport-security$') and not ps_obj.re_search_children(r'^\sshutdown$'):
        print 'switchport port-security = FAIL', ps_obj
        ps_intfs_total +=1
    else:
        ps_intfs_success += 1
        ps_intfs_total +=1

try:
    if ps_intfs_success / ps_intfs_total == 1:
        print 'switchport port-security = PASS'
except ZeroDivisionError: 
    print 'switchport port-security = FAIL - verify if switchport mode access configuration exists'

#switchport port-security violation
psv_intfs_total = 0
psv_intfs_success = 0
psv_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sswitchport\smode\saccess')
for psv_obj in psv_intfs:
    if psv_obj.re_search_children(r'^\sno\sswitchport\sport-security\sviolation') and not psv_obj.re_search_children(r'^\sshutdown$'):
        print 'switchport port-security violation = FAIL', psv_obj
        psv_intfs_total +=1
    else:
        psv_intfs_success += 1
        psv_intfs_total +=1

try:
    if psv_intfs_success / psv_intfs_total == 1:
        print 'switchport port-security violation = PASS'
except ZeroDivisionError:
    print 'switchport port-security violation = FAIL - verify if switchport mode access configuration exists'


#spanning-tree portfast
if not bool(parse.find_objects(r'^spanning-tree\sportfast\sdefault')):
    stp_intfs_total = 0
    stp_intfs_success = 0
    stp_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sswitchport\smode\saccess')
    for stp_obj in stp_intfs:
        if not stp_obj.re_search_children(r'^\sspanning-tree\sportfast') and not stp_obj.re_search_children(r'^\sshutdown$'):
            print 'spanning-tree portfast = FAIL', stp_obj
            stp_intfs_total +=1
        else:
            stp_intfs_success += 1
            stp_intfs_total +=1

    try:
        if stp_intfs_success / stp_intfs_total == 1:
            print 'spanning-tree portfast = PASS'
    except ZeroDivisionError:
        print 'spanning-tree portfast = FAIL - verify if switchport mode access configuration exists'
else:
   print 'spanning-tree portfast = PASS'


#spanning-tree portfast bpduguard
if not bool(parse.find_objects(r'^spanning-tree\sportfast\sbpduguard\sdefault')):
    stpb_intfs_total = 0
    stpb_intfs_success = 0
    stpb_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sswitchport\smode\saccess')
    for stpb_obj in stpb_intfs:
        if not stpb_obj.re_search_children(r'^\sspanning-tree\sbpduguard\senable') and not stpb_obj.re_search_children(r'^\sshutdown$'):
            print 'spanning-tree bpduguard = FAIL', stpb_obj
            stpb_intfs_total +=1
        else:
            stpb_intfs_success += 1
            stpb_intfs_total +=1
    try:
        if stpb_intfs_success / stpb_intfs_total == 1:
            print 'spanning-tree bpduguard = PASS'
    except ZeroDivisionError:
        print 'spanning-tree bpduguard = FAIL - verify if switchport mode access configuration exists'
else:
   print 'spanning-tree bpduguard = PASS'

#spanning-tree guard root
stg_intfs_total = 0
stg_intfs_success = 0
stg_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sswitchport\smode\saccess')
for stg_obj in stg_intfs:
    if not stg_obj.re_search_children(r'^\sspanning-tree\sguard\sroot') and not stg_obj.re_search_children(r'^\sshutdown$'):
        print 'spanning-tree guard root = FAIL', stg_obj
        stg_intfs_total +=1
    else:
        stg_intfs_success += 1
        stg_intfs_total +=1

try:
    if stg_intfs_success / stg_intfs_total == 1:
            print 'spanning-tree guard root = PASS'
except ZeroDivisionError:
    print 'spanning-tree guard root = FAIL - verify if switchport mode access configuration exists'

#ip proxy-arp
if not bool(parse.find_objects(r'^ip\sarp\sproxy\sdisable')):
    prx_intfs_total = 0
    prx_intfs_success = 0
    prx_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sip\saddress\s\d')
    for prx_obj in prx_intfs:
        if not prx_obj.re_search_children(r'^\sno\sip\sproxy-arp') and not prx_obj.re_search_children(r'^\sshutdown$'):
            print 'no ip proxy-arp = FAIL', prx_obj
            prx_intfs_total +=1
        else:
            prx_intfs_success += 1
            prx_intfs_total +=1
    
    try:
        if prx_intfs_success / prx_intfs_total == 1:
            print 'no ip proxy-arp = PASS'
    except ZeroDivisionError:
        print 'no ip proxy-arp = FAIL - verify ip proxy-arp configuration'

else:
   print 'no ip proxy-arp = PASS'

#ip redirects
ir_intfs_total = 0
ir_intfs_success = 0
ir_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sip\saddress\s\d')
for ir_obj in ir_intfs:
    if not ir_obj.re_search_children(r'^\sno\sip\sredirects') and not ir_obj.re_search_children(r'^\sshutdown$'):
        print 'no ip redirects = FAIL', ir_obj
        ir_intfs_total +=1
    else:
        ir_intfs_success += 1
        ir_intfs_total +=1

try:
    if ir_intfs_success / ir_intfs_total == 1:
            print 'no ip redirects = PASS'
except ZeroDivisionError:
    print 'no ip redirects = FAIL - verify ip redirects configuration'

#ip directed-broadcast
id_intfs_total = 0
id_intfs_success = 0
id_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sip\saddress\s\d')
for id_obj in id_intfs:
    if id_obj.re_search_children(r'^\sip\sdirected-broadcast') and not id_obj.re_search_children(r'^\sshutdown$'):
        print 'no ip directed-broadcast = FAIL', id_obj
        id_intfs_total +=1
    else:
        id_intfs_success += 1
        id_intfs_total +=1

try:
    if id_intfs_success / id_intfs_total == 1:
            print 'no ip directed-broadcast = PASS'
except ZeroDivisionError:
    print 'no ip directed-broadcast = FAIL - verify ip directed-broadcast configuration'

#ip unreachables
iu_intfs_total = 0
iu_intfs_success = 0
iu_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sip\saddress\s\d')
for iu_obj in iu_intfs:
    if iu_obj.re_search_children(r'^\sip\sunreachables') and not iu_obj.re_search_children(r'^\sshutdown$'):
        print 'no ip unreachables = FAIL', iu_obj
        iu_intfs_total +=1
    else:
        iu_intfs_success += 1
        iu_intfs_total +=1

try:
    if iu_intfs_success / iu_intfs_total == 1:
            print 'no ip unreachables = PASS'
except ZeroDivisionError:
    print 'no ip unreachables = FAIL - verify ip unreachables configuration'

#ip mask-reply
im_intfs_total = 0
im_intfs_success = 0
im_intfs = parse.find_objects_w_child(parentspec=r'^interf',childspec=r'^\sip\saddress\s\d')
for im_obj in im_intfs:
    if im_obj.re_search_children(r'^\sip\smask-reply') and not im_obj.re_search_children(r'^\sshutdown$'):
        print 'no ip mask-reply = FAIL', im_obj
        im_intfs_total +=1
    else:
        im_intfs_success += 1
        im_intfs_total +=1

try:
    if im_intfs_success / im_intfs_total == 1:
            print 'no ip mask-reply = PASS'
except ZeroDivisionError:
    print 'no ip mask-reply = FAIL - verify ip mask-reply configuration'


#shutdown unused ports
sup_intfs_total = 0
sup_intfs_success = 0
sup_intfs = parse.find_objects(r"^interf")
for sup_obj in sup_intfs:
    if not sup_obj.re_search_children(r'.*'):
        print 'shutdown unused ports = FAIL', sup_obj
        sup_intfs_total +=1
    else:
        sup_intfs_success += 1
        sup_intfs_total +=1

try:
    if sup_intfs_success / sup_intfs_total == 1:
            print 'shutdown unused ports = PASS'
except ZeroDivisionError:
    print 'shutdown unused ports = FAIL - verify interfaces'

print '--------end-----------'
