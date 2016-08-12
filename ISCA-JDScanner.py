#!/usr/bin/env python
#coding:utf-8


import threading
import sys
import subprocess
import re
import os
import datetime
import time
from datetime import datetime

global Counter

def single(subnet):
	global Counter
	cmd = "nmap -Pn %s --open -p 80,81,443,444,1099,5005,7001,7002,8080,8081,8083,8443,8880,8888,9000,9080,9443,16200 | grep -E 'report|open' >> tmp.txt" % (subnet)
	p = subprocess.Popen(cmd, shell=True)
	print "start using nmap to scan posible active vulnerable port for  %s" % subnet
	p.wait()
	print "nmap scan for %s is done" % subnet
	Counter -= 1


def read_file(filename):
    f = open(filename)
    content = f.readlines()
    f.close()
    return content


if __name__ == '__main__':
	while len(sys.argv)!=2:
		print "***Usage: python %s ipadrress/subnet/file. \n"
		print "For example: python %s 10.10.130.12\t  # for a single ipadrress." % sys.argv[0]
		print "For example: python %s 10.10.130.0/24\t  # for a single subnet." % sys.argv[0]
		print "For example: python %s subnets.txt\t  # for subnets in a file at pwd." % sys.argv[0]
		exit()


	if os.path.exists('tmp.txt'):
		os.remove('tmp.txt')
	if os.path.exists('target.txt'):
		os.remove('target.txt')
	if os.path.exists('result.txt'):
		os.remove('result.txt')

	startTime = datetime.now()
	Counter = 0
	lock = threading.Lock()

	if os.path.isfile(sys.argv[1]):
		lines = read_file(sys.argv[1])
		for each in lines:
			host = each.strip()
			while Counter>3:
				print "There are still %s threas running. Please be patient" % Counter
				time.sleep(10)
			t = threading.Thread(target=single,args=(host,))
			t.start()
			time.sleep(1)
			if lock.acquire():
				Counter += 1
				lock.release()
	else :
		single(sys.argv[1])


	while Counter > 0:
	    print "There are still %s threas running. Please be patient ..." % Counter
	    time.sleep(8)

	print "All nmap scans done !\nTime for nmaping these subnets is "+str(datetime.now() - startTime)[:-7] +"\n"
	time.sleep(2)


	print "Now generate the target file which contents possible host and port."
	print "You can find the target file at %s/target.txt \n" % (os.getcwd())
	time.sleep(6)
	f = open('tmp.txt','r')
	string = ""
	matchIp = re.compile(r'(?<![\.\d])((?:(?:2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(?:2[0-4]\d|25[0-5]|[01]?\d\d?))(?![\.\d])')
	matchPort = re.compile(r'\d+/tcp')
	for line in f.readlines():
	    m=''.join(matchIp.findall(line))
	    n = ''.join(matchPort.findall(line))[:-4]
	    if m != '':
	        target = m
	    if n != '':
	        string+=target+':'+n+'\n'

	r = open('target.txt','w')
	r.write(string)
	r.close()
	f.close()



	time.sleep(10)
	print "Now start to identify the hosts in target.txt"
	continu = "python ISCA-JDIdentify.py target.txt "
	p = subprocess.Popen(continu, shell=True)
	p.wait()



	print "All finished ! You can find the vulnerable hosts in %s/result.txt \n" % (os.getcwd())
	print "Total execution time: "+str(datetime.now() - startTime)[:-7] +"\n"






