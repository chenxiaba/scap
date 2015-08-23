#!/usr/bin/python
import yaml
import dpkt

import sys
import socket

"""
src cap file and filter is used to find one or more flow.
then use the conn_id to find packet in other cap file.

In order to speed to filter program
----------------------------------------------------------
0. parse packet
use dpkt to parse packet one by one, and use the filter.

1. multi thread
we must use more then one thread to do the parse work.
other cap file rely on the cap file conn_id.

One way, we parse cap file first, to find the whole info 
we need.

Other way, cap file worker and other worker running at the 
same time.

2. flow num
use flow num \ reserve num \ session time

this info can make filter pakcet much more simple:
flow num :
   how much flow you really want to filter. one or more?

reserve number:
   to prevent one flow maybe miss catch, use reserve num to
   reserve some one info.

session time:
   in normal test, a session time is aways known.
   we need't to parser the cap file over just to filter one 
   flow.

3. other
if our filter seesion is from the end, not from the begin.
then, our program still find packet from the beginning.
It's a waste of time.

how to solve this sence?

----------------------------------------------------------

"""
gconfig = None
gstat = {}
connection_table = {}

def app_init():
    global gstat

    #prepare env
    if len(sys.argv) < 2:
        app_help()
        return 

    return True

def load_conf(cfgfile):
    print "config file is %s" % cfgfile

    global gconfig

    with open(cfgfile) as f:
        gconfig = yaml.load(f)
        print gconfig

def app_help():
    print "Help:\n  python filter.py filter.yml"

def get_src_cap():
    """get src cap file"""
    captag = gconfig['cap']
    for f in gconfig['files']:
        if f['tag'] == captag:
            return f['file']

    return None


def connection_id_to_str (cid, v=4) :
    """
    This converts the connection ID cid which is a tuple of 
    (source_ip_address, source_tcp_port, 
        destination_ip_address, destination_tcp_port) 
    to a string.  
    v is either 4 for IPv4 or 6 for IPv6
    """
    if v == 4 :
        src_ip_addr_str = socket.inet_ntoa(cid[0])
        dst_ip_addr_str = socket.inet_ntoa(cid[2])
        return src_ip_addr_str + \
            ":" + str(cid[1])+ \
            "=>"+dst_ip_addr_str + \
            ":" + str(cid[3]) \

    elif v == 6 :
        src_ip_addr_str = socket.inet_ntop(AF_INET6, cid[0])
        dst_ip_addr_str = socket.inet_ntop(AF_INET6, cid[2])
        return src_ip_addr_str + \
            "." + str(cid[1])+ \
            "=>"+dst_ip_addr_str + \
            "." + str(cid[3])
    else :
        raise ValueError('Argument to connection_id_to_str must be 4 or 6, is %d' % v)

class Connection_object :
    """A connection object stores the state of the tcp connection"""
    def __init__ ( self, isn, seq, string  ) :
        # initial sequence number.  All sequence numbers are relative to this number.
        self.isn = isn     
        # last sequence number seen.  I'm not sure I need to keep this.         
        self.seq = seq   
        # the keys are the relative sequence numbers, the values are the strings                  
        self.buffer = { seq: string } 

        self.stat = {}

    def set_filter():
        pass

def decode_eth(data, filter=None):
    """
    Neet to test packet with vlan, whether type is 8021.q
    """
    eth = dpkt.ethernet.Ethernet(data)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP :
        return eth.data
    
    return None

def decode_ip(ip, filter=None):
    """Just support tcp """
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        return ip.data, ip.src, ip.dst

    return None, None, None

def decode_tcp(src, dst, tcp, filter=None):
    fin_flag = ( tcp.flags & 0x01 ) != 0
    syn_flag = ( tcp.flags & 0x02 ) != 0
    rst_flag = ( tcp.flags & 0x04 ) != 0
    psh_flag = ( tcp.flags & 0x08 ) != 0
    ack_flag = ( tcp.flags & 0x10 ) != 0
    urg_flag = ( tcp.flags & 0x20 ) != 0
    ece_flag = ( tcp.flags & 0x40 ) != 0
    cwr_flag = ( tcp.flags & 0x80 ) != 0

    #For debug
    flags = (
        ( "C" if cwr_flag else " " ) +
        ( "E" if ece_flag else " " ) +
        ( "U" if urg_flag else " " ) +
        ( "A" if ack_flag else " " ) +
        ( "P" if psh_flag else " " ) +
        ( "R" if rst_flag else " " ) +
        ( "S" if syn_flag else " " ) +
        ( "F" if fin_flag else " " )
    )

    print flags

    cid, res = get_cid((src, tcp.sport, dst, tcp.dport))

    if syn_flag and not ack_flag:
        
        if not res:
            #New flow
            connection_table[cid] = Connection_object ( 
                isn = tcp.seq, seq = tcp.seq, string = "" )
            print "Find first SYN. create table. %s" % connection_id_to_str(cid)

            return True, cid
        else:
            print "Meet retransmission SYN packet. %s" % connection_id_to_str(cid)
            return True, cid
    else:
        return False, cid
def get_filter_tcp():
    filter = gconfig['filter']
    tcp = filter['tcp']

def get_cid(cid):
    """
    find flow, if not, create it
    """
    if cid in connection_table:
        return cid, True

    conn_id = (cid[2], cid[3],cid[0],cid[1])

    if conn_id in connection_table:
        return conn_id, True

    return cid, False

def filter(capfile, filter=None):
    """Use the filter to get the packet"""

    with open(capfile) as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            ip = decode_eth(buf)
            if not ip:
                continue

            tcp, src, dst = decode_ip(ip)

            if not tcp:
                continue

            result, cid = decode_tcp(src, dst, tcp)

            if result:
                print "Find what i want now..%s" % connection_id_to_str(cid)
                with open("syn.pcap", 'w') as fwrite:
                    pwrite = dpkt.pcap.Writer(fwrite)
                    pwrite.writepkt(buf, ts)
                    pwrite.close()
                    fwrite.close();
                return

def start_work():
    """Use the info in cfg and run the filter logic"""
    src_cap = get_src_cap()

    result = filter(src_cap)

def main():
    #stat
    if not app_init():
        return

    cfg = sys.argv[1]

    load_conf(cfg)

    #start logic
    start_work()

if __name__ == "__main__":
    main()

