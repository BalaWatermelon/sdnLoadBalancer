from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host
from mininet.node import OVSKernelSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf

def MyNetwork(customTopo):
	net = Mininet(topo=customTopo, build=False, link=TCLink)
	
	info("***Adding Controller***")

	myController = net.addController(name='localController', controller=RemoteController, ip='127.0.0.1', port=6633)
	for controller in net.controllers:
		controller.start()

	net.build()
	net.start()
	CLI(net)
	net.stop()

class MyTopo(Topo):
	def __init__(self):
		
		# Initialize topology
		Topo.__init__(self)
		
		# Add hosts
		h1 = self.addHost('h1',ip='10.0.0.1')
		h2 = self.addHost('h2',ip='10.0.1.1')
		h3 = self.addHost('h3',ip='66.66.66.1')
		h4 = self.addHost('h4',ip='66.66.66.2')
		h5 = self.addHost('h5',ip='66.66.66.3')
		# Add switches
		s1 = self.addSwitch('s1',protocols='OpenFlow13')

		# Add links for s1
		self.addLink( s1, h1)
		self.addLink( s1, h2)
		self.addLink( s1, h3)
		self.addLink( s1, h4)
		self.addLink( s1, h5)

topos = {'mytopo':(lambda: MyTopo())} 

if __name__=='__main__':
	setLogLevel('info')
	MyNetwork(MyTopo())
	
