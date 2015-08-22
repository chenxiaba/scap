#!/usr/bin/python
import yaml
import sys
import dpkt
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

def load_conf(cfgfile):
	print "config file is %s" % cfgfile
	
	with open(cfgfile) as f:
		gconfig = yaml.load(f)
		print gconfig

def app_help():
	print "Help:\n  python filter.py filter.yml"


def decode_tcp(data, filter):
	pass

def decode_eth(data, filter):
	pass

def decode_ip(data, filter):
	pass



def filter():
	"""Use the info in cfg and run the filter logic"""


def main():
	#prepare env
	if len(sys.argv) < 2:
		app_help()
		return 

	cfg = sys.argv[1]

	load_conf(cfg)

	#start logic
	filter()

if __name__ == "__main__":
	main()

