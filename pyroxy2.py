#!/usr/bin/env python3
'''
 Copyright (c) 2019 anicca048
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
'''
'''
 Easily bounce packets between hosts, usefull for reverse engineering custom
 protocols.
'''

import argparse
import signal
import select
import socket
import sys

# Safe theoretical max packet data sizes (shouldn't ever be this much tho)
RECV_SIZE_TCP = ((65536 - 60) - 60)
RECV_SIZE_UDP = ((65536 - 60) - 8)

loop_entered = False
loop_stop = False

connection_sock = None
client_sock = None
relay_sock = None

# Sets up sockets and conditions for proxying loop.
def main(protocol, src_addr, src_port, dest_addr, dest_port):
	global loop_entered, loop_stop, connection_sock, client_sock, relay_sock
	# Register SIGINT handler for clean exiting while in main loop.
	signal.signal(signal.SIGINT, signal_handler)

	print("Pyroxy2")

	relay_address = (dest_addr, dest_port)

	# Build and bind client socket.
	try:
		if protocol == "tcp":
			client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	except socket.error:
		print("[!] error: failed to create client socket!")
		socket_cleanup()
		sys.exit(1)

	try:
		client_sock.bind((src_addr, src_port))
	except socket.error:
		print("[!] error: failed to bind client socket!")
		socket_cleanup()
		sys.exit(1)

	# If tcp we need to accept a connection, if udp just wait for first packet.
	if protocol == "tcp":
		print("[+] waiting for client connection.")

		# Wait for client to connect.
		client_sock.listen(1)
		connection_sock, client_address = client_sock.accept()
	else:
		print("[+] waiting for first packet.")

		pre_data, client_address = client_sock.recvfrom(RECV_SIZE_UDP)

	# Build and bind relay socket.
	try:
		if protocol == "tcp":
			relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error:
		print("[!] error: failed to create relay socket!")
		socket_cleanup()
		sys.exit(1)

	# If tcp connect to relay endpoint, if udp just relay first packet.
	if protocol == "tcp":
		print("[+] establishing relay connection.")

		# Connect to relay target.
		try:
			relay_sock.connect(relay_address)
		except socket.error:
			print("[!] error: failed to connect to relay target!")
			socket_cleanup()
			sys.exit(1)
	else:
		relay_sock.sendto(pre_data, relay_address)

	print("[+] relaying data from: ", client_address[0], ":", client_address[1],
		  " to: ", relay_address[0], ":", relay_address[1], sep='')

	# Mark that we have entered main proxy loop for exit handling.
	loop_entered = True

	# Set sockets to nonblocking and enter main packet handling / proxy loop.
	if protocol == "tcp":
		connection_sock.setblocking(0)
		relay_sock.setblocking(0)

		tcp_loop()
	else:
		client_sock.setblocking(0)
		relay_sock.setblocking(0)

		udp_loop(client_address, relay_address)

	socket_cleanup()

# Handles sigint for exit and cleanup managment.
def signal_handler(sig, frame):
	global loop_entered, loop_stop

	if not loop_entered:
		print("\r[+] exiting.")

		socket_cleanup()
		sys.exit(0)
	elif not loop_stop:
		print("\r[+] exiting.")

		loop_stop = True

# Easy socket cleanup for use in multiple places.
def socket_cleanup():
	global connection_sock, client_sock, relay_sock

	# If sockets have been created attempt to shutdown and then close.
	if connection_sock:
		try:
			connection_sock.shutdown(socket.SHUT_RDWR)
		except socket.error:
			pass
		finally:
			connection_sock.close()

	if client_sock:
		try:
			client_sock.shutdown(socket.SHUT_RDWR)
		except socket.error:
			pass
		finally:
			client_sock.close()

	if relay_sock:
		try:
			relay_sock.shutdown(socket.SHUT_RDWR)
		except socket.error:
			pass
		finally:
			relay_sock.close()

# Proxies data between two tcp connections.
def tcp_loop():
	global connection_sock, relay_sock, loop_stop

	# Use short timeout select to detect waiting data on sockets.
	while not loop_stop:
		recieved_data, var1, var2 = select.select([connection_sock, relay_sock],
												  [], [], 3)

		# Proccess all recieved packets.
		for sock in recieved_data:
			# Send data from client to relay target.
			if sock is connection_sock:
				data = connection_sock.recv(RECV_SIZE_TCP)

				if data:
					relay_sock.sendall(data)
			# Send data from relay target to client.
			elif sock is relay_sock:
				data = relay_sock.recv(RECV_SIZE_TCP)

				if data:
					connection_sock.sendall(data)

# Proxoies data between two udp connections.
def udp_loop(client_address, relay_address):
	global client_sock, relay_sock, loop_stop

	# Use short timeout select to detect waiting data on sockets.
	while not loop_stop:
		recieved_data, var1, var2 = select.select([client_sock, relay_sock],
												  [], [], 3)

		# Proccess all recieved packets.
		for sock in recieved_data:
			# Send data from client to relay target.
			if sock is client_sock:
				data = client_sock.recv(RECV_SIZE_UDP)

				if data:
					relay_sock.sendto(data, relay_address)
			# Send data from relay target to client.
			elif sock is relay_sock:
				data = relay_sock.recv(RECV_SIZE_UDP)

				if data:
					client_sock.sendto(data, client_address)

# Entry point use gaurd.
if __name__ == '__main__':
	# Create program cmdline argument parser.
	parser = argparse.ArgumentParser(
		prog="pyroxy2.py",
		description="Semi efficient tool to proxy arbitrary tcp streams. " +
		            "For when you just can't be bothered to use socks.")

	# Add arguments to parser.
	parser.add_argument("protocol", help="protocol to proxy < tcp || udp >")
	parser.add_argument("src_addr", help="source ipv4 address")
	parser.add_argument("src_port", type=int, help="source tcp port")
	parser.add_argument("dest_addr", help="destination ipv4 address")
	parser.add_argument("dest_port", type=int, help="destination tcp port")

	# Fetch arguments from sys.argv[].
	args = parser.parse_args()

	# Validate protocol argument.
	if args.protocol != "tcp" and args.protocol != "udp":
		print("error: invalid protocol!\n")
		parser.print_help(sys.stderr)
		exit(1)

	# Validate ip addr arguments.
	try:
		socket.inet_aton(args.src_addr)
	except socket.error:
		print("error: invalid source ip address!\n")
		parser.print_help(sys.stderr)
		exit(1)

	try:
		socket.inet_aton(args.dest_addr)
	except socket.error:
		print("error: invalid destination ip address!\n")
		parser.print_help(sys.stderr)
		exit(1)

	# Validate port arguments.
	if args.src_port < 1 or args.src_port > 65535:
		print("error: invalid source port address!\n")
		parser.print_help(sys.stderr)
		exit(1)

	if args.dest_port < 1 or args.dest_port > 65535:
		print("error: invalid destination port address!\n")
		parser.print_help(sys.stderr)
		exit(1)

	# Start proxy with user supplied arguments.
	main(protocol=args.protocol, src_addr=args.src_addr, src_port=args.src_port,
         dest_addr=args.dest_addr, dest_port=args.dest_port)
