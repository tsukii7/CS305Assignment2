from sockets import ICMPSocket

socket = ICMPSocket()
# ans = socket._checksum(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69')

arr='\x08\x00B\xac2\xd1\x00\x00AAAA'
for i in arr:
    print('%#x'% ord(i))

arr = b'E\x00\x00p\x00\x05\x00\x00\x80\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01g\x03\x01%\xaa\x00\x00\x00\x00E\x00\x00T\xcd\x8a\x00\x00@\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01\xbc\x08\x00T\xd5\x0eU\x00\x001h3fn0ueYjgR06TdC5yGzZwegKtJDWazgVHqsVi4frLZ0jVz2MXENk8t'
print(arr[20:28])
print(arr[28:36])
print(arr[36:44])
print(arr[44:52])
print(arr[52:54])
# ans = socket._checksum(b'\x08\x00\x00\x01\x00\x01\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69')
# print(ans)

arr = b'E\x00\x00p\x00\x05\x00\x00\x80\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01g\x03\x01%\xaa\x00\x00\x00\x00E\x00\x00T\xcd\x8a\x00\x00@\x01\x00\x00\xc0\xa8\x01g\xc0\xa8\x01\xbc\x08\x00T\xd5\x0eU\x00\x001h3fn0ueYjgR06TdC5yGzZwegKtJDWazgVHqsVi4frLZ0jVz2MXENk8t'


