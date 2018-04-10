import socket
import time

request = "GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nIf-Modified-Since: Tue, 03 Apr 2018 09:31:46 GMT\r\n\r\n"

s = socket.socket()
s.connect(('192.168.64.139', 8010))
s.send(request.format('192.168.64.139', 8010))
time.sleep(1)
data = s.recv(4096)
time.sleep(1)
s.close()
print data[9:12]
if data[9:12] == '301':
	respCode = data[9:12]
	while respCode == '301':
		print data[123:137]
		url = data[123:137]
		print type(url)
		print data[138:142]
		port = data[138:142]
		portN = int(port)
		print portN
		s2 = socket.socket()
		s2.connect((url, portN))
		s2.send(request.format(url, portN))
		time.sleep(1)
		data = s2.recv(4096)
		time.sleep(2)
		s2.close()
		print data[9:12]	
		respCode = data[9:12]


