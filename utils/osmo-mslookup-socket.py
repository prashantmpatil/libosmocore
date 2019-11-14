#!/usr/bin/env python3
import socket

MSLOOKUP_SOCKET_PATH = '/tmp/mslookup'

def query_mslookup_socket(query_str, socket_path=MSLOOKUP_SOCKET_PATH):
	mslookup_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
	mslookup_socket.connect(socket_path)
	mslookup_socket.sendall(query_str.encode('ascii'))
	result_csv = mslookup_socket.recv(1024).decode('ascii')
	return dict(zip(('query', 'result', 'v4_ip', 'v4_port', 'v6_ip', 'v6_port'),
			result_csv.split('\t')))

if __name__ == '__main__':
	import sys
	print('\nPlease run separately: osmo-mslookup-client --socket /tmp/mslookup -d\n')
	query_str = 'sip.voice.12345.msisdn'
	if len(sys.argv) > 1:
		query_str = sys.argv[1]
	print('Result: %r' % query_mslookup_socket(query_str))
