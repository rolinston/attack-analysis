# The way to reproduce the bug in the Tomcat NIO connector.
# Install python-iptables from https://github.com/ldx/python-iptables/downloads
# Author: Dmitry Kukushkin (dmitry.kukushkin at external.telekom.de)
from threading import Thread
from threading import Lock
from socket import *
from select import *
from time import *
from traceback import *
import ssl
import sys
import iptc

blockedPorts = dict()

getCssRequest = """GET /filehaha HTTP/1.1\r
Host: 10.8.146.92:443\r
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 5_0_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Mobile/9A406\r
Accept: text/css,*/*;q=0.1\r
Accept-Language: de-de\r
Accept-Encoding: gzip, deflate\r
Connection: keep-alive\r\n
\r\n
"""

class Client(Thread):
    def __init__(self, tid, lock):
        Thread.__init__(self)
        self.lock = lock
        self.tid = tid

    def run(self):
        print "Starting thread %d" % self.tid
        try:
            clientSocket = socket(AF_INET, SOCK_STREAM)
            sslSocket = ssl.wrap_socket(clientSocket)
            
            remoteAddr = ("10.8.146.92", 443)
            sslSocket.connect(remoteAddr)
            localAddr, localPort =  sslSocket.getsockname()
            print "New socket created tid=%d, sfd=%d, sport=%d" % ( self.tid, clientSocket.fileno(), localPort )
            self.deleteFirewallRule(localPort, self.lock)
            
            sslSocket.send(getCssRequest)
            data = sslSocket.recv(1024)
            ''' Put the socket into half - closed state '''
            clientSocket.shutdown(SHUT_WR)
            clientSocket.close()
            self.createFirewallRule(localPort, self.lock)
        except Exception, e:
           print "Error: ", e
           print_exc()

    @staticmethod
    def createFirewallRule(port, lock):
        lock.acquire()
        print "Creating the iptables rule for port %d" % port
        rule = iptc.Rule()
        rule.protocol = "tcp"
        rule.target = iptc.Target(rule, "REJECT")

        match = iptc.Match(rule, "tcp")
        match.sport = "%s" % port
        rule.add_match(match)
            
        chain = iptc.Chain(iptc.TABLE_FILTER, "OUTPUT")
        chain.insert_rule(rule)
        rule.target.reset()
        blockedPorts[port] = rule
        lock.release()
    
    @staticmethod
    def deleteFirewallRule(port, lock):
        lock.acquire()
        if port in blockedPorts:
            print "Deleteng the iptables rule for port %d" % port
            rule = blockedPorts[port]
            chain = iptc.Chain(iptc.TABLE_FILTER, "OUTPUT")
            chain.delete_rule(rule)
            chain.flush()
            del blockedPorts[port]
        lock.release()
        
if __name__ == "__main__":
    if len(sys.argv) == 1 :
        print "Problem.py <number of threads>"
        exit(0)
    clients = []
    lock = Lock()
    for i in range( int(sys.argv[1]) ):
        c = Client(i, lock)
        clients.append(c)
        c.start()
        
    print "Joining"
    for i in clients:
        i.join()