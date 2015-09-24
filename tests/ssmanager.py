#!/usr/bin/python
# encoding: utf-8

# 用来管理shadowsocks用户
# UNIX/LINUX环境

import os
import sys
import socket
import signal
import select

client_url = '/tmp/shadowsocks-client.sock'
manager_url = '/tmp/shadowsocks-manager.sock'

try:
	cli = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	cli.bind('/tmp/shadowsocks-client.sock')  # address of the client
	cli.connect('/tmp/shadowsocks-manager.sock')  # address of Shadowsocks manager
except:
	print "can not bind %s" % client_url
	exit(1)

cli.send(b'ping')
print(cli.recv(1506))  # You'll receive 'pong'

def handle_sigint(sig, _):
	cli.close()
	os.remove(client_url)

# 注册程序退出事件
signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handle_sigint)
signal.signal(signal.SIGINT, handle_sigint)

while True:
	try:
		rlist, wlist, elist = select.select( [sys.stdin, cli.fileno()], [], [] )
		if [rlist, wlist, elist] == [ [], [], [] ]:
			print "Five seconds elapsed.\n"
		else:
			# Loop through each socket in rlist, read and print the available data
			for sock in rlist:
				if sock is not sys.stdin:
					print cli.recv(100)
				else:
					cli.send(sock.readline().strip())
	except:
		break



