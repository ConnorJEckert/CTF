tshark -r tower_logs.pcapng -Y "modbus && ip.src == 192.168.1.252" -T fields -e modbus.reference_num | tr -d ' \t\r' | awk '{printf("%c", $1)}'



-r modbus_traffic.pcapng: read the specified .pcapng file.

-Y "modbus && ip.src == 192.168.1.100": filter only Modbus packets from the given IP.

-T fields: output only specified fields.

-e modbus.reference_num: extract just the reference_num field.





tshark -r ... -Y "modbus && ip.src == ...": filters Modbus packets from the target IP.

-T fields -e modbus.reference_num: extracts only the Modbus reference_num field.

tr -d ' \t\r': strips all whitespace.

awk '{printf("%c", $1)}': converts each decimal number to its ASCII character, printing them in a continuous string.



https://www.wireshark.org/docs/dfref/m/modbus.html#modbus.reference_num


4LR0P3Un8F-HTB{3nc2yp710n?_n3v32_h342d_0f_7h47!@^}-r6ZJa0




