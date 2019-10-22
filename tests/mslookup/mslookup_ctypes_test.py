#!/usr/bin/env python3

# Verify that using mslookup from python works

import ctypes
import time

class MsLookupException(Exception):
	pass

ID_IMSI = 'imsi'
ID_MSISDN = 'msisdn'

SERVICE_HLR_GSUP = 'gsup.hlr'
SERVICE_VOICE_SIP = 'sip.voice'
SERVICE_SMS_SMPP = 'smpp.sms'

lib = None
pending_queries = {}

try:
	lib = ctypes.cdll.LoadLibrary("libosmomslookup.so")
except:
	raise MsLookupException('''
Loading libosmomslookup failed.
If libosmocore was built with address sanitizer, try something like
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.5 my_script.py
''')

def init(init_components=('logging', 'dns')):
	global lib, IP_V4, IP_V6

	for init_component in init_components:
		name = 'osmo_mslookup_s_init_%s' % init_component
		func = getattr(lib, name)
		assert func()

	if not lib.osmo_mslookup_s_init():
		raise MsLookupException('Initializing mslookup failed (returned False)')

class Query:
	def __init__(self, id_type, id, service, request_handle, result_cb):
		self.id_type = id_type
		self.id = id
		self.service = service
		self.request_handle = request_handle
		self.result_cb = result_cb

	def __repr__(self):
		return 'mslookup.Query(%s.%s.%s, request_handle=%d)' % (
				      self.service, self.id, self.id_type,
				      self.request_handle)

	def __str__(self):
		return repr(self)

def _result_cb(request_handle, v4ip_b, v4port, v6ip_b, v6port, age):
	def decode(b):
		if not b:
			return None
		return b.decode('ascii')
	v4ip = decode(v4ip_b)
	v6ip = decode(v6ip_b)
	query = pending_queries.pop(request_handle, None)
	if query is None:
		return
	if v4ip:
		v4 = {'ip': v4ip, 'port': v4port }
	else:
		v4 = None
	if v6ip:
		v6 = {'ip': v6ip, 'port': v6port }
	else:
		v6 = None
	query.result_cb(query=query, v4=v4, v6=v6, age=age)

# see osmo_mslookup_s_callback_t
C_RESULT_CB_T = ctypes.CFUNCTYPE(None, ctypes.c_uint,
	ctypes.c_char_p, ctypes.c_uint,
	ctypes.c_char_p, ctypes.c_uint,
	ctypes.c_uint)
c_result_cb = C_RESULT_CB_T(_result_cb)

def set_logging(enabled=True, level=1):
	lib.osmo_mslookup_s_set_logging(enabled, level)

def query(id_type, id, service, result_cb, timeout=3.0):
	request_handle = lib.osmo_mslookup_s_request(ctypes.c_char_p(id_type.encode('ascii')),
						     ctypes.c_char_p(id.encode('ascii')),
						     ctypes.c_char_p(service.encode('ascii')),
						     int(timeout * 1000), c_result_cb)
	if not request_handle:
		raise MsLookupException('mslookup.query(by=%r, id=%r, service=%r) failed (returned 0)'
					% (id_type, id, service))

	query = Query(id_type, id, service, request_handle, result_cb)
	pending_queries[request_handle] = query
	return query

def cancel(query):
	cancel_handle(query.request_handle)

def cancel_handle(request_handle):
	lib.osmo_mslookup_s_request_cleanup(request_handle)

def run_test():

	def test_result_cb(**kwargs):
		print('Result:', repr(kwargs))

	init(init_components=('logging', 'fake'))
	set_logging()
	query(ID_IMSI, '1234567', SERVICE_HLR_GSUP, test_result_cb, timeout=2)
	query(ID_MSISDN, '112', SERVICE_VOICE_SIP, test_result_cb)
	query(ID_MSISDN, '0000', SERVICE_SMS_SMPP, test_result_cb, timeout=5)
	unanswered = query(ID_MSISDN, '666', SERVICE_HLR_GSUP, test_result_cb, timeout=10)

	timeout = time.time() + 6
	while time.time() < timeout:
		lib.osmo_select_main_ctx(0)

	print('canceling', unanswered)
	cancel(unanswered)
	print("done")

if __name__ == '__main__':
	run_test()

# vim: nocin ai noexpandtab ts=8 sw=8
