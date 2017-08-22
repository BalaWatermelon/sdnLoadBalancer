from ryu.lib.packet import packet
import array
'''
 Reads openflow packetin event and parse it into a list of posible packet type.
'''
class packetParser():
	def parse(self,ev):
		pktlist = packet.Packet(array.array('B', ev.msg.data))
		#for p in pktlist:
			#print p.protocol_name, p
		return pktlist
