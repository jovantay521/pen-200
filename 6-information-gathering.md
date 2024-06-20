# 6 Information Gathering
## 6.1 Passive Information Gathering
TODO
## 6.2 Active Information Gathering
### 6.2.1 DNS Enumeration
DNS Record Types
- NS: Nameserver record
- A: IPv4 address record
- AAAA: IPv6 address record
- MX: Mail Exchange record
- PTR: Pointer record (reverse lookup)
- CNAME: Canonical Name record (alias)
- TXT: Text record

#### Using `host` command

**Find Record**
```sh
host megacorpone.com
```

**Query Specific Record Type**
```sh
host -t [record_type] domain.com
```

**Brute Force DNS Records (Forward Lookup)**
```sh
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

**Brute Force DNS Records (Reverse Lookup)**
```sh
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

#### Automating with tools

**DNSRecon standard scan**
```sh
dnsrecon -d megacorpone.com -t std
```

**DNSRecon (Brute Force)**
```sh
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

**DNSEnum**
```sh
dnsenum megacorpone.com
```

#### Using `nslookup` (Windows)

**Basic Query**
```sh
nslookup mail.megacorptwo.com
```

**Specific Record Type**
```sh
nslookup -type=[record_type] domain.com DNS_server

# Example (TXT Record)
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

**Example Wordlist**
```txt
www
ftp
mail
owa
proxy
router
```

### 6.2.2 Port Scanning with Nmap
**Basic Nmap Scan**:
```bash
# Scans the 1000 most popular TCP ports on the target IP (`192.168.50.149`).
nmap 192.168.50.149
```

**Verbose and Numeric Output in iptables**:
```bash
# Lists iptables rules with verbose and numeric output.
sudo iptables -vn -L
```

**Full TCP Port Scan**:
```bash
# Scans all 65535 TCP ports on the target IP.
nmap -p 1-65535 192.168.50.149
```

**SYN Scan** (Stealth Scan):
```bash
# Performs a SYN scan, sending SYN packets to discover open ports.
sudo nmap -sS 192.168.50.149
```

**TCP Connect Scan**:
```bash
# Performs a full TCP connection scan using the three-way handshake.
nmap -sT 192.168.50.149
```

**UDP Scan**:
```bash
# Scans UDP ports using different methods to determine open/closed state.
sudo nmap -sU 192.168.50.149
```

**Combined TCP and UDP Scan**:
```bash
# Conducts a combined scan for both TCP and UDP ports.
sudo nmap -sU -sS 192.168.50.149
```

**Network Sweep (Ping Scan)**:
```bash
# Performs a network sweep to discover live hosts without port scanning.
nmap -sn 192.168.50.1-253
```

**Greppable Output**:
```bash
# Saves ping sweep results in a file (`ping-sweep.txt`) and extracts live hosts using `grep`.
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2
```

**Service Scan (Specific Port)**:
```bash
nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
grep open web-sweep.txt | cut -d" " -f2
```

**Top Ports Scan with OS Detection**:
```bash
# Scans top 20 TCP ports, performs OS detection, and saves output.
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
```

**OS Fingerprinting**:
```bash
# Attempts to identify the operating system of the target IP (`192.168.50.14`).
sudo nmap -O 192.168.50.14 --osscan-guess
```

**Service Version Detection and Script Scanning**:
```bash
# Detects service versions and runs scripts for additional information.
nmap -sT -A 192.168.50.14
```

**Nmap Scripting Engine (NSE)**:
```bash
# Runs an NSE script (`http-headers`) to gather HTTP service headers.
nmap --script http-headers 192.168.50.6
```
### 6.2.3 SMB Enumeration
**SMB Enumeration with Nmap**:
```bash
# Scan TCP ports 139 (NetBIOS) and 445 (SMB) on a range of IP addresses and save results to `smb.txt`.
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
```

**NetBIOS Information Gathering with nbtscan**:
```bash
# Perform NetBIOS name scan for hosts in the specified network range (`192.168.50.0/24`).
sudo nbtscan -r 192.168.50.0/24
```

**Nmap NSE Scripts for SMB Enumeration**:
```bash
# List available NSE scripts related to SMB in the Nmap scripts directory.
ls -1 /usr/share/nmap/scripts/smb*
```

**OS Discovery via Nmap NSE**:
```bash
# Perform OS discovery using the `smb-os-discovery` script on a specific IP (`192.168.50.152`).
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```

**Enumerating SMB Shares from Windows with net view**:
```bash
# List all shares, including administrative shares, on a specified host (`dc01`).
net view \\dc01 /all
```

### 6.2.4 SMTP Enumeration
**Using `nc` to Validate SMTP Users**:
```sh
# Connects to the SMTP server at `192.168.50.8` on port `25` and verifies the existence of the `root` and `idontexist` users.
nc -nv 192.168.50.8 25
```

**Using Python Script for SMTP User Enumeration**:
```python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <username> <target_ip>")
    sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)
print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)
print(result)

# Close the socket
s.close()
```

**Running the Python Script for SMTP User Enumeration**:
```sh
# Executes the Python script `smtp.py` to check the existence of `root` and `johndoe` users on the SMTP server at `192.168.50.8`.
python3 smtp.py root 192.168.50.8
python3 smtp.py johndoe 192.168.50.8
```

**SMTP Enumeration via PowerShell (`Test-NetConnection`)**:
```powershell
# Tests SMTP port `25` connectivity to `192.168.50.8` from PowerShell.
Test-NetConnection -Port 25 192.168.50.8
```

**Installing Telnet Client on Windows for SMTP Interaction**:
```powershell
# Installs the Telnet client on a Windows system using PowerShell's `dism` command.
dism /online /Enable-Feature /FeatureName:TelnetClient
```

**Interacting with SMTP Service via Telnet on Windows**:
```sh
# Connects to the SMTP service on `192.168.50.8` using Telnet, verifies users `goofy` and `root`.
telnet 192.168.50.8 25
```

### 6.2.5 SNMP Enumeration
**Using nmap to Perform SNMP Scan**:
```bash
# Performs a UDP scan to find open SNMP port (161) on IPs in the range `192.168.50.1-254` and saves results to `open-snmp.txt`.
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```

**Using onesixtyone to Brute Force Community Strings**:
```bash
# Creates a community file with 'public', 'private', 'manager'. Generates IP list 'ips'. Scans IPs for SNMP using onesixtyone.
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips
```

**Using snmpwalk to Enumerate Entire MIB Tree**:
```bash
# Enumerates SNMP MIB tree 
snmpwalk -c public -v1 -t 10 192.168.50.151
```

**Using snmpwalk to Enumerate Windows Users**:
```bash
# Enumerates Windows users 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
```

**Using snmpwalk to Enumerate Windows Processes**:
```bash
# Enumerates running processes 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
```

**Using snmpwalk to Enumerate Installed Software**:
```bash
# Enumerates installed software
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2
```

**Using snmpwalk to Enumerate Open TCP Ports**:
```bash
# Enumerates open TCP ports 
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```
