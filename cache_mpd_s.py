from scapy.all import *
from scapy.layers import http
import socket
import requests
import select
cache_IP = "140.123.230.71"
	
def main():
	#r = requests.get('http://140.123.230.69:1000/dash/mystream.mpd')
	Listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	Listen.connect((cache_IP, 1000))
	Listen.send('GET /dash/mystream.mpd HTTP/1.1\r\nHost: '+cache_IP+':1000\r\nUser-Agent: Mozilla/5.0 (Android 4.4.2; Mobile; rv:63.0) Gecko/63.0 Firefox/63.0\r\n'
				'Accept: video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n'
				'Range: bytes=0-\r\nReferer: '+cache_IP+':1000/test.html\r\n'
				 'Connection: keep-alive\r\nIf-None-Match: "5c91fc54-92c"\r\nCache-Control: max-age=0\r\n\r\n')			 
	Forward = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	
	temp = 0
	#cache = open("a.pcap", "w")
	#Listen.setblocking(1)
	#Listen.settimeout(0.1)
	while(1):
		total = 0
		mv_url = 0
		method =[]
		segment =[]
		y = 0
		Listen.settimeout(3.0)
		
		try:
			a = Listen.recv(1388)
			Listen.settimeout(None)
			#print "try"+str(temp)
		except socket.timeout:
			Listen.send('GET /dash/mystream.mpd HTTP/1.1\r\nHost: '+cache_IP+':1000\r\nUser-Agent: Mozilla/5.0 (Android 4.4.2; Mobile; rv:63.0) Gecko/63.0 Firefox/63.0\r\n'
				'Accept: */*\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nAccept-Encoding: gzip, deflate\r\n'
				 'Referer: '+cache_IP+':1000/test.html\r\nConnection: keep-alive\r\nIf-None-Match: "5c88b96d-920"\r\n\r\n')
			print "cache mpd"
			#print "except"+str(temp) 
			temp = 0
			look = open("mpd1.pcap","r")
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
			#print url2
		else:
			if a:
				cachefile = open("mpd"+str(temp)+".pcap", "w")
				cachefile.write(a)				
				cachefile.close()
				#x =  open("mpd"+str(temp)+".pcap", "r")
				#cache_data = x.read()
				#Forward.sendto(cache_data,("10.0.0.4",2152))
				#x.close()
				temp = temp + 1
				#print "finally"+str(temp) 
		
		
			
			
		
			
		
	
	
if __name__ == '__main__':
	main()