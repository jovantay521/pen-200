# 8 Introduction to Web Application Attacks
## 8.1 Web Application Assessment Tools
### 8.1.1 Fingerprinting Web Servers with Nmap

```sh
sudo nmap -p80 -sV <target_ip>
```

```sh
sudo nmap -p80 --script=http-enum <target_ip>
```
### 8.1.2. Directory Brute Force with Gobuster
```
gobuster dir -u <target_ip> -w /usr/share/wordlists/dirb/common.txt -t 5
```
### 8.1.3. Security Testing with Burp Suite
- intruder (brute force attack)