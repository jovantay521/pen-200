# 8 Introduction to Web Application Attacks
## 8.1 Web Application Assessment Tools
### 8.1.1 Fingerprinting Web Servers with Nmap
**Using Nmap Service Scan to Grab Web Server Banner**:
```sh
sudo nmap -p80 -sV <target_ip>
```

**Using Nmap NSE script to Fingerprint Web Server**:
```sh
sudo nmap -p80 --script=http-enum <target_ip>
```
### 8.1.2. Directory Brute Force with Gobuster
**Using Gobuster to Enumerate Files and Directories**:
```
gobuster dir -u <target_ip> -w /usr/share/wordlists/dirb/common.txt -t 5
```