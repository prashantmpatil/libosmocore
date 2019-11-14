#!/usr/bin/env python3
import subprocess
import json

def query_mslookup(query_str):
	result_line = subprocess.check_output([
		'osmo-mslookup-client', query_str, '-f', 'json'])
	result_line = result_line.decode('ascii')
	return json.loads(result_line)

if __name__ == '__main__':
	import sys
	query_str = 'sip.voice.12345.msisdn'
	if len(sys.argv) > 1:
		query_str = sys.argv[1]
	print('Result: %r' % query_mslookup(query_str))
