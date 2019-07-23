import socket
import binascii
import struct
import sysv_ipc
import string
import threading
from datetime import datetime

def write_dl_mapping_list(shm_addr, dl_tunnel_id, client_ip):
	pair_length = 95
	ttl = 1800
	
	for index in range(0, 30):
		buf1 = shm_addr.read(47, 0 + index*pair_length)
		buf2 = shm_addr.read(48, 47 + index*pair_length)
		buf1 = buf1.rstrip('\x00')
		buf2 = buf2.rstrip('\x00')
		
		if buf1 == dl_tunnel_id:
			return "existed entry"
			
	
	for index in range(0, 30):	
		buf1 = shm_addr.read(47, 0 + index*pair_length)
		buf2 = shm_addr.read(48, 47 + index*pair_length)
		if(buf1[0] == '\x00'):
			shm_addr.write(dl_tunnel_id, 0 + index*pair_length)
			shm_addr.write(client_ip, 47 + index*pair_length)
			timer = threading.Timer(ttl, delete_mapping_entry, [shm_addr, index*pair_length])
			timer.start()
			return "new entry"

	return "Memory full!"

def delete_mapping_entry(shm_addr, offset):
	blank = '\x00'
	pair_length = 95
	blank = blank * pair_length
	shm_addr.write(blank, offset)

def main():
	LOCAL_IP = "10.0.1.3"
	eNB_IP = "10.0.0.4"
	eNB_PORT = 2152
	gtp_length = 8
	ip_length = 20
	
	#recive the traffic
	ListenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	ListenSock.bind(( LOCAL_IP, 2152))
	#send the traffic
	ForwardSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	# allocate shm
	shm_addr = sysv_ipc.SharedMemory(9487, sysv_ipc.IPC_CREAT , 0666 , 4096)
	TEID_ip_mapping = sysv_ipc.attach(shm_addr.id)
	
	#sysv_ipc.remove_shared_memory() 
		
	while True:
		#print 'start'
		gtp_pkg, addr = ListenSock.recvfrom(2048)
		gtp_header = struct.unpack("!BBHL", gtp_pkg[:gtp_length])
		ip_packet = gtp_pkg[gtp_length:]
		ip_header = struct.unpack("BBHHHBBH4s4s", ip_packet[:ip_length])	
		TEID = str(gtp_header[3])
		dst_ip = socket.inet_ntoa(ip_header[9])
		src_ip = socket.inet_ntoa(ip_header[8])
		#print "{0} -> {1}".format(src_ip,dst_ip)
		'''if 'application/octet-stream' in gtp_pkg:#'HTTP/1.1 200 OK':
			print "mpd start forward time: {0}".format(datetime.now())
		if '</MPD>' in gtp_pkg:
			print "mpd end   forward time: {0}".format(datetime.now())
		if 'video/x-m4v' in gtp_pkg:
			print "x-m4v forward time: {0}".format(datetime.now())
		if 'audio/x-m4a' in gtp_pkg:
			print "x-m4a forward time: {0}".format(datetime.now())'''
		# write to shm on downlink traffic
		res = write_dl_mapping_list(TEID_ip_mapping, TEID, dst_ip)
		#print res
		ForwardSocket.sendto( gtp_pkg, ( eNB_IP, eNB_PORT ))

if __name__ == '__main__':
	main()
