import sys, struct, os.path, time, json, ipaddress, random, codecs
from socket import*
from threading import Thread

def str_from_pointer(response, p):
	i = 0
	while(response[i]!=192 and response[i+1]!=12):#start of answer
		start = i+1
		i+=1
		
	res = ""
	i = 0
	if p < start:
		stop = len(response)-p
	else:
		length = response[p-1]
		stop = p+length-1
		
	while (p < stop):
		size = response[p]
		if(size == 192):
			res += str_from_pointer(response, response[p+1])
			p+=1
			res += "."
			continue
		if(size == 0):
			break
		for j in range(1,size+1):
			res += chr(response[p+j])
		res += "."
		p += size+1
	return res

def get_ipv4(response,start):
	#name
	res = ""
	if(response[start] == 192):
		res += str_from_pointer(response, response[start+1])

	start += 12 #points to start of ip address
	ip = response[start:start+4]
	ipv4 = ""
	for j in range(0,4):
		ipv4 += str(ip[j])
		if(j != 3):
			ipv4 += "."
	return res,ipv4


def get_query_details(query):
	length = len(query)
	start = 12
	st = ""
	while start < length:
		size = query[start]
		if(size == 0):
			break
		for j in range(1,size+1):
			st += chr(query[start+j])
		st += "."
		start += size+1
	type = query[start+2]
	clas = query[start+4]
	start += 5
	return st[:len(st) - 1] ,type, clas, start

def data_packet_dns(data):
    tuple_data_dns = struct.unpack('!HHHHHH', data[:12])
    identification = tuple_data_dns[0]
    flags = tuple_data_dns[1] 
    queries = tuple_data_dns[2]
    response = tuple_data_dns[3]
    authority = tuple_data_dns[4]
    additional = tuple_data_dns[5]
    qr = (flags & 32768) != 0
    opcode = (flags & 30720 ) >> 11
    aa = (flags & 1024) != 0
    tc = (flags & 512) != 0
    rd = (flags & 256) != 0
    ra = (flags & 128) != 0
    z = (flags & 112) >> 4
    rcode = flags & 15
    return queries, response, authority, additional, rcode