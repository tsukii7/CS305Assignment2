import sys

from models import *
from time import sleep
from sockets import *
import argparse

PING_INTERVAL = 0.05
PING_TIMEOUT = 3


def ping(address,n=4, payload=None,id=None):
	if is_hostname(address):
		address = resolve(address)[0]

	sock = ICMPSocket()
	id = id or unique_identifier()
	payload = payload or random_byte_message(56)
	reply = None
	packets_sent = 0
	rtts = []

	###############################
	# TODO:
	# Create ICMPRequest and send through socket,
	# then receive and parse reply
	#
	# :type n: int
	# :param n: The number of ICMP request
	#
	# :type payload: bytes
	# :param payload: The payload in ICMP Request
	#
	# :type id: int
	# :param id: The identifier of ICMP Request
	#
	# :rtype: Host
	# :returns: ping result
	#
	# Hint: use ICMPSocket.send() to send packet and use ICMPSocket.receive() to receive
	################################

	seq = 0  # sequence number
	for _ in range(n):  # send n packets
		request = ICMPRequest(address, id, seq, payload)  # create request
		try:
			sock.send(request)  # send request
			packets_sent += 1
			seq += 1
			try:
				reply = sock.receive(request, timeout=PING_TIMEOUT)  # receive reply
				if reply.code == 0 and reply.type == 0:  # is echo reply packet
					rtts.append((reply.time - request.time) * 1000)
			except Exception:
				pass
		except Exception:
			pass
		sleep(PING_INTERVAL)

	sock.close()
	if reply:
		return Host(
			address=reply.source,
			packets_sent=packets_sent,
			rtts=rtts)
	return None


if __name__ == "__main__":
	target = sys.argv[1]
	parser = argparse.ArgumentParser(description="ping")
	parser.add_argument('--n', type=int, default=4)
	parser.add_argument('--p', type=str, default=None)
	parser.add_argument('--i', type=int, default=None)
	args = parser.parse_args(sys.argv[2:])
	n = args.n
	i = args.i
	p = None
	if args.p:
		p = args.p.encode()
	host = ping(target, n, p, i)
	print(host.__str__())
