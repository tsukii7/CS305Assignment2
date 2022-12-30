import array
from struct import pack, unpack
import platform as plt
from RawSocket_ICMP.models import ICMPReply, ICMPRequest
from RawSocket_ICMP.utils import *
from time import time
from RawSocket_ICMP.exceptions import *


class ICMPSocket:

    __slots__ = '_sock', '_address', '_privileged'

    _IP_VERSION = 4
    _ICMP_HEADER_OFFSET = 20
    _ICMP_HEADER_REAL_OFFSET = 20

    _ICMP_CODE_OFFSET = _ICMP_HEADER_OFFSET + 1
    _ICMP_CHECKSUM_OFFSET = _ICMP_HEADER_OFFSET + 2
    _ICMP_ID_OFFSET = _ICMP_HEADER_OFFSET + 4
    _ICMP_SEQUENCE_OFFSET = _ICMP_HEADER_OFFSET + 6
    _ICMP_PAYLOAD_OFFSET = _ICMP_HEADER_OFFSET + 8

    _ICMP_ECHO_REQUEST = 8
    _ICMP_ECHO_REPLY = 0

    def __init__(self, address=None, privileged=True):
        self._sock = None
        self._address = address

        # The Linux kernel allows unprivileged users to use datagram
        # sockets (SOCK_DGRAM) to send ICMP requests. This feature is
        # now supported by the majority of Unix systems.
        # Windows is not compatible.
        self._privileged = privileged or PLATFORM_WINDOWS

        try:
            sys_platform = plt.system().lower()
            if "windows" in sys_platform or "linux" in sys_platform:
                self._sock = self._create_socket(
                    socket.SOCK_RAW)
            else:
                self._sock = self._create_socket(
                    socket.SOCK_DGRAM)

            if address:
                self._sock.bind((address, 0))
        except OSError as err:
            if err.errno in (1, 13, 10013):
                try:
                    self._sock = self._create_socket(
                        socket.SOCK_DGRAM)
                except OSError:
                    raise SocketPermissionError(privileged)
            if err.errno in (-9, 49, 99, 10049, 11001):
                raise SocketAddressError(address)
            raise ICMPSocketError(str(err))

    def _create_socket(self, type):
        '''
        Create and return a new socket.

        '''
        return socket.socket(
            family=socket.AF_INET,
            type=type,
            proto=socket.IPPROTO_ICMP)

    def _set_ttl(self, ttl):
        '''
        Set the time to live of every IP packet originating from this
        socket.
        '''
        self._sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_TTL,
            ttl)

    def _checksum(self, data):
        sum = 0
        n = len(data)
        m = n % 2  # 判断data长度是否是偶数字节
        sum = 0  # 记录(十进制)相加的结果
        for i in range(0, n - m, 2):  # 将每两个字节(16位)相加（二进制求和）直到最后得出结果
            # if i == 2:
            #     continue
            # if i < 8:
            sum += data[i+1] + (data[i ] << 8)
            # else:
            #     sum += (data[i+1]) + (data[i]) << 8  # 传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
        if m:  # 传入的data长度是奇数，将执行，且把这个字节（8位）加到前面的结果
            sum += data[-1]
        # # 将高于16位与低16位相加
        # sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)  # 如果还有高于16位，将继续与低16位相加
        sum = ~sum & 0xffff  # 对sum取反(返回的是十进制)
        return sum

    def _check_data(self, data, checksum):
        result = self._checksum(data)
        return result == checksum

    def _create_packet(self, request: ICMPRequest):
        id = request.id  # 13009 32D1
        sequence = request.sequence  # 0
        payload = request.payload
        checksum = 0
        code = 0
        type = 8
        ans = type
        ans = ans << 8
        ans = ans + code   # type code
        ans = ans << 16  # type code checksum
        ans = ans << 16
        ans = ans + id   # type code checksum id
        ans = ans << 16
        ans = ans + sequence  # type code checksum id seq
        size = len(payload)
        # print("*************")
        # print(size)
        ans = ans << size * 8

        ans = ans + int.from_bytes(payload, 'big')
        t = ans.to_bytes(8+size, 'big')
        checksum = self._checksum(t)
        # print(checksum)
        checksum = checksum << (size * 8 + 4 * 8)
        ans = ans + checksum
        answer = ans.to_bytes(size + 8, 'big')
        return answer

    def _parse_reply(self, packet, source, current_time):
        sequence = 0
        type = 0
        code = 0
        # TODO:
        # Parse an ICMP reply from bytes.
        #
        # Read sequence, type and code from packet 
        #
        # :type packet: bytes
        # :param packet: IP packet with ICMP as its payload
        #
        # :rtype: ICMPReply
        # :returns: an ICMPReply parsed from packet
        return ICMPReply(
            source=source,
            id=id,
            sequence=sequence,
            type=type,
            code=code,
            time=current_time)

    def send(self, request):
        '''
        Send an ICMP request message over the network to a remote host.

        This operation is non-blocking. Use the `receive` method to get
        the reply.

        :type request: ICMPRequest
        :param request: The ICMP request you have created. If the socket
            is used in non-privileged mode on a Linux system, the
            identifier defined in the request will be replaced by the
            kernel.

        :raises SocketBroadcastError: If a broadcast address is used and
            the corresponding option is not enabled on the socket
            (ICMPv4 only).
        :raises SocketUnavailableError: If the socket is closed.
        :raises ICMPSocketError: If another error occurs while sending.

        '''
        if not self._sock:
            raise SocketUnavailableError

        try:
            sock_destination = socket.getaddrinfo(
                host=request.destination,
                port=None,
                family=self._sock.family,
                type=self._sock.type)[0][4]

            packet = self._create_packet(request)

            self._set_ttl(request.ttl)
            # self._set_traffic_class(request.traffic_class)

            request._time = time()
            self._sock.sendto(packet, sock_destination)

            # On Linux, the ICMP request identifier is replaced by the
            # kernel with a random port number when a datagram socket is
            # used (SOCK_DGRAM). So, we update the request created by
            # the user to take this new identifier into account.
            if not self._privileged and PLATFORM_LINUX:
                request._id = self._sock.getsockname()[1]

        except PermissionError:
            raise SocketBroadcastError

        except OSError as err:
            raise ICMPSocketError(str(err))

    def receive(self, request=None, timeout=2):
        '''
        Receive an ICMP reply message from the socket.

        This method can be called multiple times if you expect several
        responses as with a broadcast address.

        :type request: ICMPRequest, optional
        :param request: The ICMP request to use to match the response.
            By default, all ICMP packets arriving on the socket are
            returned.

        :type timeout: int or float, optional
        :param timeout: The maximum waiting time for receiving the
            response in seconds. Default to 2.

        :rtype: ICMPReply
        :returns: An `ICMPReply` object representing the response of the
            desired destination or an upstream gateway. See the
            `ICMPReply` class for details.

        :raises TimeoutExceeded: If no response is received before the
            timeout specified in parameters.
        :raises SocketUnavailableError: If the socket is closed.
        :raises ICMPSocketError: If another error occurs while receiving.

        '''
        if not self._sock:
            raise SocketUnavailableError

        self._sock.settimeout(timeout)
        time_limit = time() + timeout

        try:
            while True:
                response = self._sock.recvfrom(1024)
                current_time = time()

                packet = response[0]
                source = response[1][0]

                if current_time > time_limit:
                    raise socket.timeout

                reply = self._parse_reply(
                    packet=packet,
                    source=source,
                    current_time=current_time)

                if (reply and not request or
                    reply and request.id == reply.id and
                    request.sequence == reply.sequence):
                    return reply

        except socket.timeout:
            raise TimeoutExceeded(timeout)

        except OSError as err:
            raise ICMPSocketError(str(err))

    def close(self):
        '''
        Close the socket. It cannot be used after this call.

        '''
        if self._sock:
            self._sock.close()
            self._sock = None



