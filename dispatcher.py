import socket
import binascii
import struct
from datetime import datetime
from random import randint

first_ack = 0

def checksum(data):
	s = 0
	n = len(data) % 2
	for i in range(0, len(data)-n, 2):
		s+= ord(data[i]) + (ord(data[i+1]) << 8)
	if n:
		s+= ord(data[i+1])
	while (s >> 16):
		s = (s & 0xFFFF) + (s >> 16)
	s = ~s & 0xffff
	return s
class up_ip():
	def __init__(self, source, destination, id_udprand, payload='', proto=socket.IPPROTO_TCP):
		self.version = 4
		self.ihl = 5  # Internet Header Length
		self.tos = 0  # Type of Service
		self.tl = 20 + len(payload)
		self.id = id_udprand  # random.randint(0, 65535)
		self.flags = 0  # Don't fragment
		self.offset = 0
		self.ttl = 64
		self.protocol = proto
		self.checksum = 0  # will be filled by kernel
		self.source = socket.inet_aton(source)
		self.destination = socket.inet_aton(destination)
 		
	def pack(self):
		ver_ihl = (self.version << 4) + self.ihl
		flags_offset = (self.flags << 13) + self.offset
		ip_header = struct.pack("!BBHHHBBH4s4s",
								ver_ihl,
								self.tos,
								self.tl,
								self.id,
								0x4000,
								self.ttl,
								self.protocol,
								self.checksum,
								self.source,
								self.destination)
		self.checksum = checksum(ip_header)
		ip_header = struct.pack("!BBHHHBBH4s4s",
								ver_ihl,
								self.tos,
								self.tl,
								self.id,
								0x4000,
								self.ttl,
								self.protocol,
								socket.htons(self.checksum),
								self.source,
								self.destination)
		return ip_header
class UDP():
	def __init__(self, src, dst, payload=''):
	# def __init__(self, src, dst):
		self.src = src
		self.dst = dst
		self.payload = payload
		self.checksum = 0
		self.length = 8  # UDP Header length
 
	def pack(self, src, dst, proto=socket.IPPROTO_UDP):
		length = self.length + len(self.payload)
		#print str(length)+"----------"
		pseudo_header = struct.pack('!4s4sBBH',
									socket.inet_aton(src), socket.inet_aton(dst), 0,
									proto, length)
		self.checksum = checksum(pseudo_header)
		packet = struct.pack('!HHHH',
							 self.src, self.dst, length, self.checksum)
		return packet 
class ip():
 
	def __init__(self, source, destination, id_tcprand,payload=''):
		self.version = 4
		self.ihl = 5 # Internet Header Length
		self.tos = 0 # Type of Service
		self.tl = 0#20 + payload# total length will be filled by kernel
		self.id = id_tcprand
		self.flags = 0 # More fragments
		self.offset = 0
		self.ttl = 63
		self.protocol = socket.IPPROTO_TCP
		self.checksum = 0 # will be filled by kernel
		self.source = socket.inet_aton(source)
		self.destination = socket.inet_aton(destination)
 		
	def pack(self):
		ver_ihl = (self.version << 4) + self.ihl
		flags_offset = (self.flags << 13) + self.offset
		ip_header = struct.pack("!BBHHHBBH4s4s",
					ver_ihl,
					self.tos,
					self.tl,
					self.id,
					0x4000,
					self.ttl,
					self.protocol,
					self.checksum,
					self.source,
					self.destination)
		self.checksum = checksum(ip_header)
		ip_header = struct.pack("!BBHHHBBH4s4s",
					ver_ihl,
					self.tos,
					self.tl,
					self.id,
					0x4000,
					self.ttl,
					self.protocol,
					self.checksum,
					self.source,
					self.destination)
		return ip_header
 
class tcp():
 
	def __init__(self, srcp, dstp, ack, psh, seqn, ackn, data=""):
		self.srcp = srcp
		self.dstp = dstp
		self.seqn = ackn
		self.ackn = seqn
		self.offset = 5 # Data offset: 5x4 = 20 bytes
		self.reserved = 0
		self.urg = 0
		self.ack = ack
		self.psh = psh
		self.rst = 0
		self.syn = 0
		self.fin = 0
		self.window = socket.htons(5840)
		self.checksum = 0
		self.urgp = 0
		self.payload = data
 
	def pack(self, source, destination):
		data_offset = (self.offset << 4) + 0
		flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
		tcp_header = struct.pack("!HHLLBBHHH",
					 self.srcp,
					 self.dstp,
					 self.seqn,
					 self.ackn,
					 data_offset,
					 flags, 
					 self.window,
					 self.checksum,
					 self.urgp)
		#pseudo header fields
		source_ip = source
		destination_ip = destination
		reserved = 0
		protocol = socket.IPPROTO_TCP
		total_length = len(tcp_header) + len(self.payload)
		# Pseudo header
		psh = struct.pack("!4s4sBBH",
			  source_ip,
			  destination_ip,
			  reserved,
			  protocol,
			  total_length)
		psh = psh + tcp_header + self.payload
		tcp_checksum = checksum(psh)
		tcp_header = struct.pack("!HHLLBBH",
				  self.srcp,
				  self.dstp,
				  self.seqn,
				  self.ackn,
				  data_offset,
				  flags,
				  self.window)
		tcp_header+= struct.pack("H", tcp_checksum) + struct.pack("!H", self.urgp)
		return tcp_header
def m4vsend(source,site, port, seqn, ackn, py_len):
	#s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	src_host=source
	dest_host=socket.gethostbyname(site)
	randnumber = randint(1, 65535)
	id_udprand = randint(1, 65535)
	id_tcprand = randint(1, 65535)
	#print dest_host	
	global 	first_ack
	for x in range(447):
		'''if x == 0 and first_ack == 1:
			ack = 1
			psh = 0
			seqn = seqn + py_len
			tcpobj=tcp(1000,port, ack, psh, seqn, ackn)
			tcph=tcpobj.pack(src_host,dest_host)
			tcp_len = len(tcph)
			ipobj=ip(src_host,dest_host,id_tcprand, tcp_len)
			iph=ipobj.pack()
			GTP_len = len(iph + tcph)
			GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0xd36cf116)
			udp = UDP(randnumber, 2152, GTP_header + iph + tcph).pack("10.0.1.2","10.0.0.4")
			ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
			#packet = ip_udp + udp + GTP_header +iph + tcph
			packet = iph + tcph 
			s.sendto(packet,("10.0.0.4",2152))
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1'''
			
		if x == 0 :
			ack = 1
			psh = 0
			seqn = seqn + py_len
			#print "m4v start time: {0}".format(datetime.now())+"+++++++++++++++"
		elif x == 446:
			ack = 1
			psh = 1
			ackn = ackn + tcp_segment_len	
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1
			print "m4v end time: {0}".format(datetime.now())+"+++++++++++++++++++"
		else:
			ack = 1
			psh = 0
			ackn = ackn + tcp_segment_len	
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1		
			
		#print seqn, py_len
		ipobj=ip(src_host,dest_host,id_tcprand)
		iph=ipobj.pack()
		cachefile = open("m4v"+str(x)+".pcap", "r")
		cache_data = cachefile.read()
		#cache_data = "123"
		tcp_segment_len = len(cache_data)
		tcpobj=tcp(1000,port, ack, psh, seqn, ackn, cache_data)
		#tcpobj.data_length=len(data)
		#print tcpobj.data_length
		tcph=tcpobj.pack(ipobj.source,ipobj.destination)
		# Injection
		GTP_len = len(iph + tcph + cache_data)
		GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0xca6fe0dd)
		udp = UDP(randnumber, 2152, GTP_header + iph + tcph + cache_data).pack("10.0.1.2","10.0.0.4")
		ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
		packet = ip_udp + udp + GTP_header +iph + tcph + cache_data
		#packet = iph + tcph + cache_data
		#print len(packet)
		s.sendto(packet,("10.0.0.4",2152))
		cachefile.close()
		#print first
	s.close()
def m4asend(source,site, port, seqn, ackn, py_len):
	#s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	src_host=source
	dest_host=socket.gethostbyname(site)
	randnumber = randint(1, 65535)
	id_udprand = randint(1, 65535)
	id_tcprand = randint(1, 65535)
	#print dest_host	
	global 	first_ack
	for x in range(5):
		'''if x == 0 and first_ack == 1:
			ack = 1
			psh = 0
			seqn = seqn + py_len
			tcpobj=tcp(1000,port, ack, psh, seqn, ackn)
			tcph=tcpobj.pack(src_host,dest_host)
			tcp_len = len(tcph)
			ipobj=ip(src_host,dest_host,id_tcprand, tcp_len)
			iph=ipobj.pack()
			GTP_len = len(iph + tcph)
			GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0xd36cf116)
			udp = UDP(randnumber, 2152, GTP_header + iph + tcph).pack("10.0.1.2","10.0.0.4")
			ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
			#packet = ip_udp + udp + GTP_header +iph + tcph
			packet = iph + tcph 
			s.sendto(packet,("10.0.0.4",2152))
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1'''
			
		if x == 0 :
			ack = 1
			psh = 0
			seqn = seqn + py_len
			#print "m4a start time: {0}".format(datetime.now())+"+++++++++++++++"
		elif x == 4:
			ack = 1
			psh = 1
			ackn = ackn + tcp_segment_len	
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1
			print "m4a end time: {0}".format(datetime.now())+"+++++++++++++++++++"
		else:
			ack = 1
			psh = 0
			ackn = ackn + tcp_segment_len	
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1		
			
		#print seqn, py_len
		ipobj=ip(src_host,dest_host,id_tcprand)
		iph=ipobj.pack()
		cachefile = open("m4a"+str(x)+".pcap", "r")
		cache_data = cachefile.read()
		#cache_data = "123"
		tcp_segment_len = len(cache_data)
		tcpobj=tcp(1000,port, ack, psh, seqn, ackn, cache_data)
		#tcpobj.data_length=len(data)
		#print tcpobj.data_length
		tcph=tcpobj.pack(ipobj.source,ipobj.destination)
		# Injection
		GTP_len = len(iph + tcph + cache_data)
		GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0xca6fe0dd)
		udp = UDP(randnumber, 2152, GTP_header + iph + tcph + cache_data).pack("10.0.1.2","10.0.0.4")
		ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
		packet = ip_udp + udp + GTP_header +iph + tcph + cache_data
		#packet = iph + tcph + cache_data
		#print len(packet)
		s.sendto(packet,("10.0.0.4",2152))
		cachefile.close()
		#print first
	s.close()
def mpdsend(source,site, port, seqn, ackn, py_len):
	#s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	src_host=source
	dest_host=socket.gethostbyname(site)
	randnumber = randint(1, 65535)
	id_udprand = randint(1, 65535)
	id_tcprand = randint(1, 65535)
	#print dest_host
	# IP Header
	
	#print ipobj
	
	# TCP Header
	global 	first_ack
	for x in range(2):
		if x == 0 and first_ack == 1:
			ack = 1
			psh = 0
			seqn = seqn + py_len
			tcpobj=tcp(1000,port, ack, psh, seqn, ackn)
			tcph=tcpobj.pack(src_host,dest_host)
			tcp_len = len(tcph)
			ipobj=ip(src_host,dest_host,id_tcprand, tcp_len)
			iph=ipobj.pack()
			GTP_len = len(iph + tcph)
			GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0xca6fe0dd)
			udp = UDP(randnumber, 2152, GTP_header + iph + tcph).pack("10.0.1.2","10.0.0.4")
			ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
			packet = ip_udp + udp + GTP_header +iph + tcph
			#packet = iph + tcph 
			s.sendto(packet,("10.0.0.4",2152))
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1
			
		if x == 0 :
			if first_ack == 1:
				ack = 1
				psh = 0
				
			else:
				ack = 1
				psh = 0
				seqn = seqn + py_len
				#print "mpd start time: {0}".format(datetime.now())
		else:
			ack = 1
			psh = 1
			ackn = ackn + tcp_segment_len	
			id_udprand = id_udprand + 1
			id_tcprand = id_tcprand + 1
			print "mpd end time: {0}".format(datetime.now())
		#print seqn, py_len
		ipobj=ip(src_host,dest_host,id_tcprand)
		iph=ipobj.pack()
		cachefile = open("mpd"+str(x)+".pcap", "r")
		cache_data = cachefile.read()
		#cache_data = "123"
		tcp_segment_len = len(cache_data)
		tcpobj=tcp(1000,port, ack, psh, seqn, ackn, cache_data)
		#tcpobj.data_length=len(data)
		#print tcpobj.data_length
		tcph=tcpobj.pack(ipobj.source,ipobj.destination)
		see  = struct.unpack("!s", iph[5])
		#print see
		# Injection
		GTP_len = len(iph + tcph + cache_data)
		GTP_header = struct.pack("!BBHL",0x38, 0xff, GTP_len, 0x7f3abb37)
		udp = UDP(randnumber, 2152, GTP_header + iph + tcph + cache_data).pack("10.0.1.2","10.0.0.4")
		ip_udp = up_ip("10.0.1.2","10.0.0.4", id_udprand, udp, proto=socket.IPPROTO_UDP).pack()
		packet = ip_udp + udp + GTP_header +iph + tcph + cache_data
		#packet = iph + tcph + cache_data
		#print len(packet)
		s.sendto(packet,("10.0.0.4",2152))
		cachefile.close()
		#print first
	s.close()

def catch_url():
	total = 0
	y = 0
	method =[]
	segment =[]
	look = open("mpd0.pcap","r")
	file = look.read()
	#print file
	for x in file:
		total = total + 1	
		'''if x =='\n' :
			mv_url = mv_url + 1'''
		method.append(x)
		url = ("".join(method))
		if '<S t="' in url and y == 0 :
			y = 1
		elif  y == 1:
			if x == '"':
				y = 2
				continue
			segment.append(x)	
	url = ("".join(method))
	url2 = ("".join(segment))

	return url2
def getHeadInfo(raw_packet, tunnel_exist_flag) :

	gtp_length = 8
	ip_length = 20
	udp_length = 8
	tcp_length = 20
	udp_dport = 0
	http_length = 60
	sport = 0
	seqn = 0
	ackn = 0
	payload_len = 0
	
	# registered mec servers, add your service ip into the list
	server_list = []
	server_list.append("10.0.1.2")
	server_list.append("10.0.2.5")
	server_list.append("10.0.2.2")
	server_list.append("10.0.2.101")
	
	# get gtp header
	gtp_header = struct.unpack("!BBHL", raw_packet[:gtp_length])
	
	# get ip header
	ip_packet = raw_packet[gtp_length:]
	ip_header = struct.unpack("BBHHHBBH4s4s", ip_packet[:ip_length])
	IHL = (ip_header[0] & 0xf) * 4
	if ip_header[6] == 6: #tcp
		tcp_packet = ip_packet[IHL:]
		tcp_header = struct.unpack("!HH", tcp_packet[:4])
	elif ip_header[6] == 17: #udp
				udp_packet = ip_packet[IHL:]
				udp_header = struct.unpack("!HHHH", udp_packet[:udp_length])
				udp_sport = udp_header[0]
				udp_dport = udp_header[1]
	http_url = raw_packet[http_length:]
	
	

	#!1s1s1H1H2s1B1B2s4s4s ip_header
	#"!HHII2sH2sH"tcpheader
	mv_url = catch_url()
	#print mv_url+"+++++++++++++++++++++++++++++"
	
	if "GET /dash/mystream.mpd" in http_url:		
		stop = 4
		http_request_content = http_url.decode("utf-8")
		#print http_request_content	 
		#print "+++++"+"mpd get time: {0}".format(datetime.now())+"+++++"
		tcp_port = raw_packet[28:40]
		#print tcp_port		
		port = struct.unpack("!HHII", tcp_port)
		#print port[2],port[3]
		sport = port[0]
		seqn = port[2]
		ackn = port[3]	
		#print "+++"+socket.inet_ntoa(port[0])+"+++"+socket.inet_ntoa(port[1])	
		#print len(http_url)
		payload_len = len(http_url)
		global 	first_ack 
		first_ack = first_ack + 1
	else:
		stop = 0
	if ("GET /dash/mystream-" in http_url and ".m4a" in http_url) or ("GET /dash/mystream-" in http_url and ".m4v" in http_url):
	#if ("GET /dash/mystream_2-" in http_url and ".m4a" in http_url) or ("GET /dash/mystream_2-" in http_url and ".m4v" in http_url):
		#print mv_url
		#print http_url
		#print "+++++"+"get time: {0}".format(datetime.now())+"+++++"
		tcp_port = raw_packet[28:40]
		port = struct.unpack("!HHII", tcp_port)
		#print port[2],port[3]
		sport = port[0]
		seqn = port[2]
		ackn = port[3]	
		payload_len = len(http_url)
		if ("GET /dash/mystream-" in http_url and ".m4a" in http_url):
			#print "+++++"+"get time: {0}".format(datetime.now())+"+++++"
		#if ("GET /dash/mystream_2-" in http_url and ".m4a" in http_url):
			stop = 2
		if ("GET /dash/mystream-" in http_url and ".m4v" in http_url):	
			print "+++++"+"get time: {0}".format(datetime.now())+"+++++"
		#if ("GET /dash/mystream_2-" in http_url and ".m4v" in http_url):
			stop = 3
	
	#print first_ack
	#print stop		
	#print ("tunnel_exist_flag")
	src = socket.inet_ntoa(ip_header[8])
	des = socket.inet_ntoa(ip_header[9])
	#print "{0} => {1}".format(src, des)
	
	for i in server_list:	
		if socket.inet_ntoa(ip_header[9]) == i or (tunnel_exist_flag == 1 and udp_dport == 53):
				return True, 0, socket.inet_ntoa(ip_header[8]), stop, sport, seqn, ackn, payload_len
	return False, 0, socket.inet_ntoa(ip_header[8]), stop, sport, seqn, ackn, payload_len


def main() :
	LOCAL_IP = "10.0.1.2"	# bind address of this module
	CORE_IP = "10.0.0.1"#"172.17.100.254" 
	CORE_PORT = 2152
	MEC_IP = "10.0.1.2"		# bind address of up_link_gtp_handler 
	MEC_PORT = 7000 
	cache_IP = "140.123.230.71"
	global first_ack
	first_ack = 0
	#recive the traffic
	ListenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ListenSock.bind(( LOCAL_IP, 2152)) 
	ForwardSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
	seq = 0	
	while True:		 
		gtp_pkg, addr = ListenSock.recvfrom(2048)
		seq+=1
		header = gtp_pkg[:28]
			
			
		#print "received addr:", addr
		#print ("sequence number: {0}".format(seq))
		# get header info
		if(seq == 1):   
			Redirection, firstack, src_ip, stop_value, sport, seqnumber, acknumber, payload_len = getHeadInfo(gtp_pkg, 0)
		else:
			Redirection, firstack, src_ip, stop_value, sport, seqnumber, acknumber, payload_len = getHeadInfo(gtp_pkg, 1)
		#print stop_value
		#print  first_ack
		if Redirection :
			check = gtp_pkg[60:]
			
			l = ForwardSocket.sendto(gtp_pkg,( MEC_IP, MEC_PORT ))
			
			#print "----------------sending to MEC server."+str(stop_value)+"--------------------"
			
		else :
			check = gtp_pkg[60:]
			#http_request_content = check.decode("utf-8")
			#print http_request_content
			if stop_value == 1:
				#print src_ip
				mpdsend(cache_IP,src_ip, sport, seqnumber, acknumber, payload_len)
				print "mpd forward"
			elif stop_value == 2:
				m4asend(cache_IP,src_ip, sport, seqnumber, acknumber, payload_len)
				print "m4a forward"
			elif stop_value == 3:
				m4vsend(cache_IP,src_ip, sport, seqnumber, acknumber, payload_len)
				print "m4v forward"
			else:
				ForwardSocket.sendto( gtp_pkg, ( CORE_IP, CORE_PORT ))
				#print "sending to Core..."
			ForwardSocket.sendto( gtp_pkg, ( CORE_IP, CORE_PORT ))
			#print ""
	

	
if __name__ == '__main__' :
	main()




