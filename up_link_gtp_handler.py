import socket
import struct
import binascii

def carry_around_add(a, b):
	c = a + b
	return (c & 0xffff) + (c >> 16)


def checksum(msg):
	s = 0 
	for i in range(0, len(msg), 2):
		w = (ord(msg[i]) << 8) + ord(msg[i+1])
		s = carry_around_add(s,w)
	return ~s & 0xffff

def getHeaderInfo( raw_packet ):
	# header length
	gtp_length = 8
	ip_length = 20
	udp_length = 8
	tcp_length = 20
	
	# get gtp header
	gtp_header = struct.unpack( "!BBHL", raw_packet[:gtp_length] )
	# get ip header
	ip_packet = raw_packet[gtp_length:]
	ip_header = struct.unpack( "!BBHHHBBH4s4s", ip_packet[:ip_length] )
	
	# changed IP header info 
	new_ip_len = 0
	new_ip_checksum = 0 
	ip_dest = socket.inet_ntoa(ip_header[9])
	if(socket.inet_ntoa(ip_header[9]) == '8.8.8.8' or socket.inet_ntoa(ip_header[9]) == '8.8.4.4'):
		ip_dest = '10.0.1.2'
	new_ip_dst = socket.inet_pton( socket.AF_INET, ip_dest )

	# new IP header
	new_ip_header = struct.pack('!BBHHHBBH4s4s', ip_header[0], ip_header[1], new_ip_len, ip_header[3], ip_header[4], ip_header[5], ip_header[6], new_ip_checksum, ip_header[8], new_ip_dst )
	print ("{0}->{1}".format(socket.inet_ntoa(ip_header[8]), socket.inet_ntoa(new_ip_dst)))

	# caculate IHL
	IHL = ( ip_header[0] & 0xf ) * 4

	if ip_header[6] == 6 :
		# TCP
		tcp_packet = ip_packet[IHL:]
		tcp_header = struct.unpack("!HHLLBBHHH", tcp_packet[:tcp_length])
		payload_data = tcp_packet[tcp_length:]
		# new tcp header without checksum
		tcp_checksum = 0
		dst = socket.inet_ntoa(ip_header[9])

		new_tcp_header = struct.pack("!HHLLBBHHH", tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4], tcp_header[5], tcp_header[6], tcp_checksum, tcp_header[8])

		# caculate pseudo ip header
		psh_saddr = ip_header[8]
		psh_daddr = new_ip_dst
		psh_reserved = 0
		psh_protocol = socket.IPPROTO_TCP
		psh_tcp_len = len(new_tcp_header) + len( payload_data)
		psh = struct.pack("!4s4sBBH", psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_tcp_len)
		# caculate the checksum
		chk = psh + new_tcp_header + payload_data
		if len(chk) % 2 != 0 :
			chk+='\0'

		tcp_checksum = checksum(chk)
		# new tcp header with checksum
		new_tcp_header = struct.pack("!HHLLBBH", tcp_header[0], tcp_header[1], tcp_header[2], tcp_header[3], tcp_header[4], tcp_header[5], tcp_header[6] ) + struct.pack("!H", tcp_checksum ) + struct.pack("!H", tcp_header[8])
		# return the packet
		print ("{0}->{1}".format(socket.inet_ntoa(tcp_header[8]), socket.inet_ntoa(ip_header[9])))
		return True, new_ip_header + new_tcp_header + payload_data, ip_header[6], ip_header[9]

	elif ip_header[6] == 17 :
		# UDP
		udp_packet = ip_packet[IHL:]
		udp_header = struct.unpack("!HHHH", udp_packet[:udp_length])
		payload_data = udp_packet[udp_length:]
		# new udp header without checksum
		udp_checksum = 0
		new_udp_header = struct.pack("!HHHH", udp_header[0], udp_header[1], udp_header[2], udp_checksum )
		#caculate pseudo ip header
		psh_saddr = ip_header[8]
		psh_daddr = new_ip_dst
		psh_reserved = 0 
		psh_protocol = socket.IPPROTO_UDP
		psh_udp_len = udp_header[2]
		psh = struct.pack("!4s4sBBH", psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_udp_len)
		# caculate the checksum 
		chk = psh + new_udp_header + payload_data
		if len(chk) % 2 != 0 :
			chk+='\0'

		udp_checksum = checksum(chk)

		# new udp header with checksum
		new_udp_header = struct.pack("!HHHH", udp_header[0], udp_header[1], udp_header[2],udp_checksum)

		# return the packet
		 #print ("{0}->{1}".format(socket.inet_ntoa(tcp_header[8]), socket.inet_ntoa(ip_header[9])))
		return True, new_ip_header + new_udp_header + payload_data, ip_header[6], ip_header[9]
	elif ip_header[6] == 1:
		icmp_packet = ip_packet[IHL:]
		icmp_header = icmp_packet[:4]
		payload_data = icmp_packet[4:]
		return True, new_ip_header + icmp_header + payload_data, ip_header[6], ip_header[9]
	else :
		return False, "", ""

def main():
	seq = 0 
	address = ( '10.0.1.2', 7000 )

	listen_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
	listen_sock.bind( address )
	Redirec_sock = socket.socket( socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) 
	
	while True:
		print "sequence number: ", seq 
		seq = seq + 1
		gtp_pkg, addr = listen_sock.recvfrom(4096)
		print "received from : ", addr
		isSup, packet, protocol, dst = getHeaderInfo( gtp_pkg )
		dst = socket.inet_ntoa(dst)  #network to str
		#print dst
		if(dst == '8.8.8.8' or dst == '8.8.4.4'):
			dst = '10.0.1.2'  # DNS server bind address
		if isSup :
			#a = packet[28:]
			print "Redirect to local MEC server , protocol: {0}, dest: {1}".format(protocol, dst)
			#c = struct.unpack("!HH", a[:4])
			#print c
			#print ip_header[9]
			#print socket.inet_ntoa(ip_header[9])
			#print b
			Redirec_sock.sendto(packet, (dst, 0))
		else:
			print "this type not support yet"


	listen_sock.close()
if __name__ == '__main__':
	main()
