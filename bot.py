from engine.network.network import *
from engine.client import Client

addr = NetAddr()
addr.ip = bytearray("192.168.56.1".encode())
addr.port = 8303


x = Client()
x.run(addr)
# doesn't work


