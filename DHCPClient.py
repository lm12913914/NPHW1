import socket
import uuid
import struct

def get_dhcp_option(packet, opCode):
    op_index = 240
    while packet[op_index] != 255:
        #print(packet[op_index])
        len = packet[op_index+1]
        if packet[op_index] == opCode:
            return packet[op_index+2:op_index+2+len]
        op_index += len+2
    

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.bind(('',16800))

mymac=int(input('Input client MAC:\n'),16).to_bytes(6, 'big')
#mymac=uuid.getnode().to_bytes(6, 'big')
magic_cookie=b'\x63\x82\x53\x63'

#======================DHCPDiscover=====================# 
pkg=b'\x01\x01\x06\x00\x11\x22\x33\x44' + (b'\x00'*20) + mymac + (b'\x00'*202) + magic_cookie
pkg+=b'\x35\x01\x01'     #DHCP Discover
pkg+=b'\xff\x00\x00'     #end
 
s.sendto(pkg,("255.255.255.255",16700))
#======================DHCPDiscover=====================#

(a,b)=s.recvfrom(1000)
print('DHCP Offer Pkg recieved!!\nPkg fields:\n')
print('OP:','0x%02X'%struct.unpack('!B',a[0:1]),'\tHTYP:','0x%02X'%struct.unpack('!B',a[1:2]),'\tHLEN:','0x%02X'%struct.unpack('!B',a[2:3]),'\tHOPS:','0x%02X'%struct.unpack('!B',a[3:4]))
print('XID:','0x%08X'%struct.unpack('!I', a[4:8]))
print('SECS:','0x%04X'%struct.unpack('!H', a[8:10]),'FLAGS:','0x%04X'%struct.unpack('!H', a[10:12]))
print('CIADDR:','0x%08X'%struct.unpack('!I', a[12:16]))
print('YIADDR:','0x%08X'%struct.unpack('!I', a[16:20]))
print('SIADDR:','0x%08X'%struct.unpack('!I', a[20:24]))
print('GIADDR:','0x%08X'%struct.unpack('!I', a[24:28]))
print('CHADDR:','0x%08X'%struct.unpack('!I', a[28:32]),'\t','0x%08X'%struct.unpack('!I', a[32:36]),'\t','0x%08X'%struct.unpack('!I', a[36:40]),'\t','0x%08X'%struct.unpack('!I', a[40:44]))
print('Magic Cookie:','0x%08X'%struct.unpack('!I', a[236:240]))
print('DHCP option 53:','0x%02X'%struct.unpack('!B', get_dhcp_option(a,53)),'\tDHCP Offer:',[int(b)for b in get_dhcp_option(a,53)])
print('DHCP option 1:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,1)),'\tsubnet mask:',[int(b)for b in get_dhcp_option(a,1)])
print('DHCP option 3:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,3)),'\trouter:',[int(b)for b in get_dhcp_option(a,3)])
print('DHCP option 51:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,51)),'\tIP lease time:',[int(b)for b in get_dhcp_option(a,51)])
print('DHCP option 54:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,54)),'\tDHCP server:',[int(b)for b in get_dhcp_option(a,54)])
print('\n')
#======================DHCPREQUEST======================#
 
pkg=b'\x01\x01\x06\x00\x11\x22\x33\x44' + (b'\x00'*20) + mymac + (b'\x00'*202) + magic_cookie
pkg+=b'\x35\x01\x03'     #DHCP Request
pkg+=b'\x32\x04' + a[16:20]
pkg+=b'\x36\x04' + get_dhcp_option(a, 54)
pkg+=b'\xff\x00\x00'     #end
 
s.sendto(pkg,("255.255.255.255",16700))
#======================DHCPREQUEST======================#

(a,b)=s.recvfrom(1000)
print('DHCP Ack Pkg recieved!!\nPkg fields:\n')
print('OP:','0x%02X'%struct.unpack('!B',a[0:1]),'\tHTYP:','0x%02X'%struct.unpack('!B',a[1:2]),'\tHLEN:','0x%02X'%struct.unpack('!B',a[2:3]),'\tHOPS:','0x%02X'%struct.unpack('!B',a[3:4]))
print('XID:','0x%08X'%struct.unpack('!I', a[4:8]))
print('SECS:','0x%04X'%struct.unpack('!H', a[8:10]),'FLAGS:','0x%04X'%struct.unpack('!H', a[10:12]))
print('CIADDR:','0x%08X'%struct.unpack('!I', a[12:16]))
print('YIADDR:','0x%08X'%struct.unpack('!I', a[16:20]))
print('SIADDR:','0x%08X'%struct.unpack('!I', a[20:24]))
print('GIADDR:','0x%08X'%struct.unpack('!I', a[24:28]))
print('CHADDR:','0x%08X'%struct.unpack('!I', a[28:32]),'\t','0x%08X'%struct.unpack('!I', a[32:36]),'\t','0x%08X'%struct.unpack('!I', a[36:40]),'\t','0x%08X'%struct.unpack('!I', a[40:44]))
print('Magic Cookie:','0x%08X'%struct.unpack('!I', a[236:240]))
print('DHCP option 53:','0x%02X'%struct.unpack('!B', get_dhcp_option(a,53)),'\tDHCP Ack:',[int(b)for b in get_dhcp_option(a,53)])
print('DHCP option 1:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,1)),'\tsubnet mask:',[int(b)for b in get_dhcp_option(a,1)])
print('DHCP option 3:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,3)),'\trouter:',[int(b)for b in get_dhcp_option(a,3)])
print('DHCP option 51:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,51)),'\tIP lease time:',[int(b)for b in get_dhcp_option(a,51)])
print('DHCP option 54:','0x%08X'%struct.unpack('!I', get_dhcp_option(a,54)),'\tDHCP server:',[int(b)for b in get_dhcp_option(a,54)])

print('Now you have IP:', "0x%08X"%struct.unpack('!I', a[16:20])[0], '\t', [int (b) for b in a[16:20]])
input()
