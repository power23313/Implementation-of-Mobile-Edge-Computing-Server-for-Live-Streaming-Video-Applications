import socket
import binascii
import struct
import multiprocessing as mp
import sysv_ipc
import time
from datetime import datetime

def carry_around_add(a, b):
	c = a + b
	return ( c & 0xffff) + ( c >> 16 )

def checksum_ip(msg):
	s = 0
	for i in range(0, len(msg), 2):
		w = ord(msg[i]) + (ord(msg[i+1]) << 8)
		s = carry_around_add(s,w)
	return ~s & 0xffff

def checksum(msg):
	s = 0
	for i in range(0, len(msg), 2):
		w = (ord(msg[i]) << 8) + ord(msg[i+1])
		s = carry_around_add(s,w)
	return ~s & 0xffff

def src_ip_spoof(packet):
	# header legth
	ip_length = 20
	udp_length = 8
	tcp_length = 20 
	# default setting
  	# get ip header info
	ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:ip_length] )

	# chaneged IP header info
	new_ip_checksum = 0

	# caculate IHL
	IHL = ( ip_header[0] & 0xf ) * 4
	# set pseudo ip header
	psh_daddr = ip_header[9]
	psh_reserved = 0

	if ip_header[6] == 6:
		# TCP
		tcp_packet = packet[IHL:]
		tcp_header = struct.unpack("!HHLLBBHHH", tcp_packet[:tcp_length])
		payload_data = tcp_packet[tcp_length:]
		# new tcp header info without checksum
		tcp_checksum = 0
		new_tcp_header = struct.pack("!HHLLBBHHH", tcp_header[0],tcp_header[1],tcp_header[2],tcp_header[3],tcp_header[4],tcp_header[5],tcp_header[6],tcp_checksum,tcp_header[8])
 		#caculate pseudo ip header
		src = socket.inet_ntoa(ip_header[8])
		new_ip_src = socket.inet_pton( socket.AF_INET, src ) #ip_src
		# new ip header
		new_ip_header = struct.pack("!BBHHHBBH4s4s", ip_header[0], ip_header[1], ip_header[2], ip_header[3], ip_header[4], ip_header[5], ip_header[6], new_ip_checksum, ip_header[8], ip_header[9])
		psh_saddr = new_ip_src
		psh_protocol = socket.IPPROTO_TCP
		psh_tcp_len = len(new_tcp_header) + len(payload_data)
		psh = struct.pack("!4s4sBBH", psh_saddr,psh_daddr,psh_reserved,psh_protocol,psh_tcp_len)
		# caculate the checksum
		chk = psh + new_tcp_header + payload_data
		if len(chk) % 2 != 0:
			chk+='\0'
		tcp_checksum = checksum(chk)
		
		# new tcp header with cheksum
		new_tcp_header = struct.pack("!HHLLBBHHH",tcp_header[0],tcp_header[1],tcp_header[2],tcp_header[3],tcp_header[4],tcp_header[5],tcp_header[6],tcp_checksum, tcp_header[8])
		
		# new ip header with checksum
		chk = new_ip_header 
		if len(chk) % 2 != 0 :
			chk+='\0'

		new_ip_checksum = checksum_ip(chk)

		new_ip_header = struct.pack("!BBHHHBB", ip_header[0],ip_header[1],ip_header[2],ip_header[3],ip_header[4],ip_header[5],ip_header[6])
		new_ip_header = new_ip_header + struct.pack("H",new_ip_checksum) +struct.pack("!4s4s", new_ip_src, ip_header[9])

		return True, new_ip_header + new_tcp_header + payload_data, ip_header[6]

	elif ip_header[6] == 17:
		#UDP
		udp_packet = packet[IHL:]
		udp_header = struct.unpack("!HHHH", udp_packet[:udp_length])
		payload_data = udp_packet[udp_length:]
		ip_src = socket.inet_ntoa(ip_header[8])
		if udp_header[0] == 53:
			#print "udp.src_ip: {0}".format(socket.inet_ntoa(psh_saddr))
			ip_src = '8.8.8.8'
		new_ip_src = socket.inet_pton( socket.AF_INET, ip_src )
		psh_saddr = new_ip_src
		new_ip_header = struct.pack("!BBHHHBBH4s4s", ip_header[0],ip_header[1],ip_header[2],ip_header[3],ip_header[4],ip_header[5],ip_header[6],new_ip_checksum,new_ip_src,ip_header[9])
		

		# new udp header without checksum
		udp_checksum = 0 
		new_udp_header = struct.pack("!HHHH", udp_header[0], udp_header[1], udp_header[2],udp_checksum)
		# caculate pseudo ip header
		psh_protocol = socket.IPPROTO_UDP
		psh_udp_len = udp_header[2]
		psh = struct.pack("!4s4sBBH", psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_udp_len)
		# caculate the checksum
		chk = psh + new_udp_header + payload_data
		if len(chk) % 2 != 0 :
			chk+='\0'

		udp_checksum = checksum(chk)

		# new udp header with checksum
		new_udp_header = struct.pack("!HHHH", udp_header[0], udp_header[1], udp_header[2], udp_checksum )
		# new ip header withe checksum
		
		chk = new_ip_header 
		if len(chk) % 2 != 0 :
			chk+='\0'

		new_ip_checksum = checksum_ip(chk)

		new_ip_header = struct.pack("!BBHHHBB", ip_header[0],ip_header[1],ip_header[2],ip_header[3],ip_header[4],ip_header[5],ip_header[6])
		new_ip_header = new_ip_header + struct.pack("H",new_ip_checksum) +struct.pack("!4s4s", new_ip_src, ip_header[9])
		return True, new_ip_header + new_udp_header + payload_data, ip_header[6]
	elif ip_header[6] == 1:
		icmp_packet = packet[IHL:]
		icmp_header = struct.unpack("!BBH", icmp_packet[:4])
		payload_data = icmp_packet[4:]
		new_ip_header = struct.pack("!BBHHHBBH4s4s", ip_header[0],ip_header[1],ip_header[2],ip_header[3],ip_header[4],ip_header[5],ip_header[6],new_ip_checksum,ip_header[8],ip_header[9])# ip_header[8] -> new_ip_src
		
		
		# new icmp header without checksum
		icmp_checksum = 0
		new_icmp_header = struct.pack("!BBH", icmp_header[0], icmp_header[1], icmp_checksum)
		
		#psh_protocol = socket.IPPROTO_ICM33               3#psh_icmp_len = icmp_header[2]
		#psh = struct.pack("!4s4sBBH", psh_saddr, psh_daddr, psh_reserved, psh_protocol, psh_icmp_len)
		# caculate the checksum
		chk = new_icmp_header + payload_data
		if len(chk) % 2 != 0 :
		        chk+='\0'
		
		icmp_checksum = checksum(chk)
		
		# new udp header with checksum
		new_icmp_header = struct.pack("!BBH", icmp_header[0], icmp_header[1], icmp_checksum )
		# new ip header withe checksum
		
		chk = new_ip_header
		if len(chk) % 2 != 0 :
		        chk+='\0'
		
		new_ip_checksum = checksum_ip(chk)
		new_ip_header = struct.pack("!BBHHHBB", ip_header[0],ip_header[1],ip_header[2],ip_header[3],ip_header[4],ip_header[5],ip_header[6])
                new_ip_header = new_ip_header + struct.pack("H",new_ip_checksum) +struct.pack("!4s4s", ip_header[8], ip_header[9])#ip_header[8] -> new_ip_src

		return True, new_ip_header + new_icmp_header + payload_data, ip_header[6]
	else:
		return False, ""



def find_TEID(shm_addr, dst_ip):
	pair_length = 95
	for index in range(0, 30):
		buf1 = shm_addr.read(47, 0 + index*pair_length)
		buf2 = shm_addr.read(48, 47 + index*pair_length)
		buf1 = buf1.rstrip('\x00')
		buf2 = buf2.rstrip('\x00')	
		if(buf2 == dst_ip):
			return buf1
	return -1	


def main():
	

	
	raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # 0x0003 = ETH_P_ALL
	gtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	shm_addr = sysv_ipc.SharedMemory(9487, sysv_ipc.IPC_CREAT , 0666 , 4096)
	TEID_IP_mapping = sysv_ipc.attach(shm_addr.id)

	eth_length = 14
	ip_length = 20
	seq = 0
	header_length = eth_length + ip_length
	cnt = 0
	#print 'start'	
	while True :
		packet = raw_sock.recvfrom(8192)[0]
		#print "start time: ", datetime.now().microsecond/1000.0
		header = struct.unpack("!6s6s2sBBHHHBBH4s4s", packet[:header_length])
		#if header[0][0:6] == b'\x9c\x5c\x8e\xbb\x7d\x06':   # link layer MAC address
		if 1:
			src_ip = socket.inet_ntoa(header[11])
			des_ip = socket.inet_ntoa(header[12])
			if(des_ip[0:7] == "192.188"):                   # UE subnet prefix
				tunnel = find_TEID(TEID_IP_mapping, des_ip)
					#print tunnel
				if tunnel == -1:
					print "tunnel not found"
				else:
					print ("From: {0} -> To {1}".format(src_ip, des_ip))
					ip_packet = packet[eth_length:]
						#print "start time: ", datetime.now().microsecond/1000.0, ", ", datetime.now(), ", len=", len(packet) 
					isSup, new_packet, protocol = src_ip_spoof(ip_packet)
					if isSup :
						print "Add GTP header, protocol: {0}".format(protocol)
							#gtp_header = struct.pack("!BBHL",56,255,len(new_packet),3396329693)
						gtp_header = struct.pack("!BBHL",56,255,len(new_packet),int(tunnel))
						packet = gtp_header + new_packet
							#print "end time: ", datetime.now().microsecond/1000.0, ", ", datetime.now(), ", len=", len(packet)
						gtp_sock.sendto( packet,("10.0.0.4", 2152))
							#print "Return to user..."
					else:
						print "not Sup"
						pass

			else:
				pass
	

if __name__=='__main__':
	main()
