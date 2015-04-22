import socket
import uuid
import struct
def get_new_ip(left_bound, right_bound):
    current = left_bound
    while used_ip[current]!=0:
        current = current + 1
    if current <= right_bound:
        used_ip[current] = 1
        return current
    else:
        return 1000
def get_dhcp_option(packet, opCode):
    op_index = 240
    while packet[op_index] != 255:
        #print(packet[op_index])
        len = packet[op_index+1]
        if packet[op_index] == opCode:
            return packet[op_index+2:op_index+2+len]
        op_index += len+2
ip=input('Input server IP:\n')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.bind((ip,16700))
magic_cookie=b'\x63\x82\x53\x63'
used_ip=[0]*256
(a,b)=s.recvfrom(1000)
print('DHCP Discover Pkg recieved!!\nPkg fields:\n')
print('OP:','0x%02X'%struct.unpack('!B',a[0:1]),'\tHTYP:','0x%02X'%struct.unpack('!B',a[1:2]),'\tHLEN:','0x%02X'%struct.unpack('!B',a[2:3]),'\tHOPS:','0x%02X'%struct.unpack('!B',a[3:4]))
print('XID:','0x%08X'%struct.unpack('!I', a[4:8]))
print('SECS:','0x%04X'%struct.unpack('!H', a[8:10]),'FLAGS:','0x%04X'%struct.unpack('!H', a[10:12]))
print('CIADDR:','0x%08X'%struct.unpack('!I', a[12:16]))
print('YIADDR:','0x%08X'%struct.unpack('!I', a[16:20]))
print('SIADDR:','0x%08X'%struct.unpack('!I', a[20:24]))
print('GIADDR:','0x%08X'%struct.unpack('!I', a[24:28]))
print('CHADDR:','0x%08X'%struct.unpack('!I', a[28:32]),'\t','0x%08X'%struct.unpack('!I', a[32:36]),'\t','0x%08X'%struct.unpack('!I', a[36:40]),'\t','0x%08X'%struct.unpack('!I', a[40:44]))
print('Magic Cookie:','0x%08X'%struct.unpack('!I', a[236:240]))
print('DHCP option 53:','0x%02X'%struct.unpack('!B', get_dhcp_option(a,53)),'\tDHCP Discover:',[int(b)for b in get_dhcp_option(a,53)])
print('\n\n\n\n')
#======================DHCPOffer=====================#
new_ip=get_new_ip(10, 255)
if new_ip==1000: print('no left ip for you\n')
pkg =b'\x02\x01\x06\x00\x11\x22\x33\x44'
pkg+= (b'\x00'*8)
pkg+= b'\xc0\xa8\x01' + bytes([new_ip]) #192.168.1.new_ip
pkg+= (b'\x00'*8)
pkg+= a[28:34]
pkg+= (b'\x00'*202)
pkg+= magic_cookie
pkg+=b'\x35\x01\x02'     #DHCP Offer
pkg+=b'\x01\x04\xff\xff\xff\x00'#subnet mask=255.255.255.0
pkg+=b'\x03\x04\xc0\xa8\x01\x01'#rounterr=192.168.1.1
pkg+=b'\x33\x04\x00\xff\xff\xff'#ip lease time in units of seconds
pkg+=b'\x36\x04'+bytes([int(i)for i in ip.split('.')])#DHCP server=ip
pkg+=b'\xff\x00\x00'     #end
 
s.sendto(pkg,("255.255.255.255",16800))
#======================DHCPOffer=====================#

(a,b)=s.recvfrom(1000)
print('DHCP request Pkg recieved!!\nPkg fields:\n')
print('OP:','0x%02X'%struct.unpack('!B',a[0:1]),'\tHTYP:','0x%02X'%struct.unpack('!B',a[1:2]),'\tHLEN:','0x%02X'%struct.unpack('!B',a[2:3]),'\tHOPS:','0x%02X'%struct.unpack('!B',a[3:4]))
print('XID:','0x%08X'%struct.unpack('!I', a[4:8]))
print('SECS:','0x%04X'%struct.unpack('!H', a[8:10]),'FLAGS:','0x%04X'%struct.unpack('!H', a[10:12]))
print('CIADDR:','0x%08X'%struct.unpack('!I', a[12:16]))
print('YIADDR:','0x%08X'%struct.unpack('!I', a[16:20]))
print('SIADDR:','0x%08X'%struct.unpack('!I', a[20:24]))
print('GIADDR:','0x%08X'%struct.unpack('!I', a[24:28]))
print('CHADDR:','0x%08X'%struct.unpack('!I', a[28:32]),'\t','0x%08X'%struct.unpack('!I', a[32:36]),'\t','0x%08X'%struct.unpack('!I', a[36:40]),'\t','0x%08X'%struct.unpack('!I', a[40:44]))
print('Magic Cookie:','0x%08X'%struct.unpack('!I', a[236:240]))
print('DHCP option 53:','0x%02X'%struct.unpack('!B', get_dhcp_option(a,53)),'\tDHCP Request:',[int(b)for b in get_dhcp_option(a,53)])
print('DHCP option 50:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,50)),'\trequested:',[int(b)for b in get_dhcp_option(a,50)])
print('DHCP option 54:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,54)),'\tDHCP server:',[int(b)for b in get_dhcp_option(a,54)])
print('\n\n\n')



#======================DHCPAck======================#
 
pkg =b'\x02\x01\x06\x00\x11\x22\x33\x44'
pkg+= (b'\x00'*8)
pkg+= b'\xc0\xa8\x01' + bytes([new_ip]) #192.168.1.new_ip
pkg+= (b'\x00'*8)
pkg+= a[28:34]
pkg+= (b'\x00'*202)
pkg+= magic_cookie
pkg+=b'\x35\x01\x05'     #DHCP Ack
pkg+=b'\x01\x04\xff\xff\xff\x00'#subnet mask=255.255.255.0
pkg+=b'\x03\x04\xc0\xa8\x01\x01'#rounterr=192.168.1.1
pkg+=b'\x33\x04\x00\xff\xff\xff'#ip lease time in units of seconds
pkg+=b'\x36\x04'+bytes([int(i)for i in ip.split('.')])#DHCP server=ip
pkg+=b'\xff\x00\x00'     #end
 
s.sendto(pkg,("255.255.255.255",16800))
#======================DHCPAck======================#
input()
