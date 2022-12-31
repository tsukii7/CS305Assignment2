import argparse
import sys

from models import *
from time import sleep
from sockets import *

PING_COUNT = 3  #the number of ICMP echo packet tobe sent whose initial TTL value are same  
PING_INTERVAL = 0.05
PING_TIMEOUT = 2
MAX_HOP = 30


def tracert(address, id=None):
    if is_hostname(address):
        address = resolve(address)[0]

    sock = ICMPSocket()

    id = id or unique_identifier()
    ttl = 1
    host_reached = False
    hops = []

    seq = 0  # set sequence number

    while not host_reached and ttl <= MAX_HOP:
        reply = None
        packets_sent = 0
        rtts = []

        ###############################
        # TODO:
        # Create ICMPRequest and send through socket,
        # then receive and parse reply,
        # remember to modify ttl when creating ICMPRequest
        #
        #
        # :type id: int
        # :param id: The identifier of ICMP Request
        #
        # :rtype: Host[]
        # :returns: ping result
        #
        # Hint: use ICMPSocket.send() to send packet and use ICMPSocket.receive() to receive
        #
        ################################

        for _ in range(PING_COUNT):
            request = ICMPRequest(destination=address,
                                  id=id,
                                  sequence=seq,
                                  ttl=ttl)
            try:
                sock.send(request)
                packets_sent += 1
                seq += 1
                try:
                    reply = sock.receive(request, timeout=PING_TIMEOUT)
                    if reply.type == 0 and reply.code == 0:  # 收到回复 到达目的地
                        host_reached = True
                        rtts.append((reply.time - request.time) * 1000)
                    elif reply.type == 11 and reply.code == 0:  # ttl超时 未抵达目的地
                        rtts.append((reply.time - request.time) * 1000)
                except Exception:
                    pass
            except Exception as e:
                print(e.args[0])
                pass
            sleep(PING_INTERVAL)

        if reply:
            hop = Hop(
                address=reply.source,
                packets_sent=packets_sent,
                rtts=rtts,
                distance=ttl)

            hops.append(hop)

        ttl += 1

    sock.close()
    return hops


if __name__ == "__main__":
    target = sys.argv[1]
    parser = argparse.ArgumentParser(description="tracert")
    parser.add_argument('--i', type=int, default=None)
    args = parser.parse_args(sys.argv[2:])
    hops = tracert(target,args.i)
    for hop in hops:
        print(hop.__str__())
