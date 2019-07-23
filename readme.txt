1. connect MEC to eNB and to CN with two cables
2. copy dnsmasq.conf under /etc
3. run dnsmasq(sudo dnsmasq)
4. modify arp_sh to match your interface name
5. change subnet ip if you have different settings
6. run arp_sh 
7. run dispatcher.py, down_link_gtp_handler.py, forwarding_downlink.py, up_link_gtp_handler.py
8. check connectivity to Internet and to your MEC



sudo /etc/init.d/dnsmasq restart 
netstat -tupln

123


