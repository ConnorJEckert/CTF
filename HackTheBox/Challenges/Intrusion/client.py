#!/usr/bin/python3

import socket
from time import sleep
from umodbus import conf
from umodbus.client import tcp

# Adjust modbus configuration
conf.SIGNED_VALUES = True

# Create a socket connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
sock.connect(('127.0.0.1', 502)) # CHANGE THE IP & PORT to the dockers instance

# write your umodbus command here
# command = 

# Send your message to the network
tcp.send_message(command, sock)

# Use sleep between messages 
sleep(1)

# Close the connection
sock.close()
