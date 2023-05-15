from engine.network.network import *
from engine.client import Client

addr = NetAddr()
addr.ip = bytearray("127.0.0.1".encode())
addr.port = 8303


x = Client()
x.run(addr)
# doesn't work


