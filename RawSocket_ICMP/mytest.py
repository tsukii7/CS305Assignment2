from sockets import ICMPSocket

socket = ICMPSocket()
# ans = socket._checksum(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69')
# arr='abcd'
# for i in arr:
#     print('%#x'%ord(i))
ans = socket._checksum(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69')
print(ans)

