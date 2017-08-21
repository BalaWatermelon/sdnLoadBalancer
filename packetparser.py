from ryu.lib.packet import packet

'''
 Reads openflow packetin event and parse it into a list of posible packet type.
'''
class packetParser():
	def __init__(self,ev):
		
	def parse(self,ev):
		pkt = packet.Packet(array.array('B', ev.msg.data))
	    	for p in pkt:
			print p.protocol_name, p
			if p.protocol_name == 'vlan':
		    		print 'vid = ', p.vid
		return pkt
