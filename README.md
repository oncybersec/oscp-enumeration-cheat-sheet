# OSCP Enumeration Cheat Sheet

A collection of commands and tools used for conducting enumeration during my OSCP journey.

## Description

This is an enumeration cheat sheet that I created while pursuing the OSCP. It also includes the commands that I used on platforms such as Vulnhub and Hack the Box. Some of these commands are based on those executed by the [Autorecon](https://github.com/Tib3rius/AutoRecon) tool.

## Disclaimer

This cheat sheet should not be considered to be complete and only represents a snapshot in time when I used these commands for performing enumeration during my OSCP journey. These commands should only be used for educational purposes or authorised testing.

Table of Contents
=================

* [Enumeration](#enumeration)
  * [Host](#host)
    * [Nmap](#nmap)
    * [Proxychains](#proxychains)
    * [Autorecon](#autorecon)
  * [Services](#services)
    * [FTP (21/tcp)](#ftp-21tcp)
    * [SSH (22/tcp)](#ssh-22tcp)
    * [SMTP (25/tcp)](#smtp-25tcp)
    * [DNS (53/tcp, 53/udp)](#dns-53tcp-53udp)
    * [HTTP/HTTPS (80/tcp, 443/tcp)](#httphttps-80tcp-443tcp)
    * [Kerberos (88/tcp, 464/tcp)](#kerberos-88tcp-464tcp)
    * [POP3/POP3S (110/tcp, 995/tcp)](#pop3pop3s-110tcp-995tcp)
    * [RPC (111/tcp, 135/tcp)](#rpc-111tcp-135tcp)
    * [ident (113/tcp)](#ident-113tcp)
    * [NTP (123/udp)](#ntp-123udp)
    * [NetBIOS-NS (137/udp)](#netbios-ns-137udp)
    * [SMB (139/tcp, 445/tcp)](#smb-139tcp-445tcp)
    * [IMAP/IMAPS (143/tcp, 993/tcp)](#imapimaps-143tcp-993tcp)
    * [SNMP (161/udp)](#snmp-161udp)
    * [LDAP (389/tcp, 3268/tcp)](#ldap-389tcp-3268tcp)
    * [Java RMI (1100/tcp)](#java-rmi-1100tcp)
    * [MSSQL (1433/tcp)](#mssql-1433tcp)
    * [Oracle TNS listener (1521/tcp)](#oracle-tns-listener-1521tcp)
    * [NFS (2049/tcp)](#nfs-2049tcp)
    * [MySQL (3306/tcp)](#mysql-3306tcp)
    * [RDP (3389/tcp)](#rdp-3389tcp)
    * [SIP (5060/udp)](#sip-5060udp)
    * [PostgreSQL (5432/tcp)](#postgresql-5432tcp)
    * [VNC (5900/tcp)](#vnc-5900tcp)
    * [AJP (8009/tcp)](#ajp-8009tcp)
  * [Active Directory](#active-directory)

# Enumeration

## Host

### Nmap

```text
# Full TCP port scan
sudo nmap -Pn -p- -oN alltcp_ports.txt $ip

# Full TCP port scan (safe scripts + version detection)
sudo nmap -Pn -sC -sV -p- -oN alltcp.txt $ip

# Top 20 UDP port scan
sudo nmap -Pn -sU -sV -sC --top-ports=20 -oN top_20_udp_nmap.txt $ip
```

### Proxychains

```text
# Top 20 TCP port scan
proxychains nmap -Pn -sT --top-ports=20 --open -oN top_20_tcp_nmap.txt $ip

# Top 1000 TCP port scan
proxychains nmap -Pn -sT --top-ports=1000 --open -oN top_1000_tcp_nmap.txt $ip

# Scan TCP ports (safe scripts + version detection)
proxychains nmap -Pn -sT -sC -sV -p 21,22,80 -oN tcp_nmap_sC_sV.txt $ip
```

### Autorecon

```text
# Scan single target
sudo autorecon -o enumeration $ip

# Scan multiple targets
sudo autorecon -o enumeration $ip1 $ip2 $ip3 $ip4
```

## Services

### FTP (21/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 21 --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_21_ftp_nmap.txt" $ip
```

### SSH (22/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oN tcp_22_ssh_nmap.txt $ip
```

### SMTP (25/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 25 "--script=banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN tcp_25_smtp_nmap.txt $ip
```

[smtp-user-enum](https://pypi.org/project/smtp-user-enum)

```text
/home/kali/.local/bin/smtp-user-enum -V -m RCPT -w -f '<user@example.com>' -d 'domain.local' -U "/usr/share/metasploit-framework/data/wordlists/unix_users.txt" $ip 25 2>&1 | tee "tcp_25_smtp_user-enum.txt"
```

### DNS (53/tcp, 53/udp)

```text
# Version detection + NSE scripts
sudo nmap -Pn -sU -sV -p 53 "--script=banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN udp_53_dns_nmap.txt $ip
```

```text
# Perform zone transfer (only works over port 53/tcp)
dig axfr @$ip $domain 2>&1 | tee "tcp_53_dns_dig.txt"

# Perform reverse DNS lookup (may display NS record containing domain name)
nslookup $ip $ip

# Brute force subdomains
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 16 -o "tcp_53_dns_gobuster.txt"
```

### HTTP/HTTPS (80/tcp, 443/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN tcp_port_protocol_nmap.txt $ip
```

**Nikto**

```text
nikto -h $url 2>&1 | tee "tcp_port_protocol_nikto.txt"
```

**Directory brute force**

```text
gobuster dir -u $url -w /usr/share/seclists/Discovery/Web-Content/common.txt -x "txt,html,php,asp,aspx,jsp" -s "200,204,301,302,307,403,500" -k -t 16 -o "tcp_port_protocol_gobuster.txt"  

python3 /opt/dirsearch/dirsearch.py -u $url -t 16 -e txt,html,php,asp,aspx,jsp -f -x 403 -w /usr/share/seclists/Discovery/Web-Content/common.txt --plain-text-report="tcp_port_protocol_dirsearch.txt"

Dirbuster (GUI): only perform extension brute force - disable 'Brute Force Dirs'

wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -t 16 $url/FUZZ 2>&1 | tee "tcp_port_http_wfuzz.txt"

# Directory brute force recursively with max depth = 2
python3 /opt/dirsearch/dirsearch.py -u $url/apps/ -t 16 -e txt,html,php -f -x 403 -r -R 2 -w /usr/share/seclists/Discovery/Web-Content/common.txt --plain-text-report="tcp_port_protocol_dirsearch_apps.txt"
```

**Whatweb**

```text
whatweb --color=never --no-errors -a 3 -v $url 2>&1 | tee "tcp_port_protocol_whatweb.txt"
```

**Wordpress**

```text
# Enumerate vulnerable plugins and themes, timthumbs, wp-config.php backups, database exports, usernames and media IDs
wpscan --url $url --no-update --disable-tls-checks -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee tcp_port_protocol_wpscan.txt

# Enumerate all plugins
wpscan --url $url --disable-tls-checks --no-update -e ap --plugins-detection aggressive -f cli-no-color 2>&1 | tee tcp_port_protocol_wpscan_plugins.txt
```

**Robots.txt**

```text
/robots.txt
```

**Only get HTTP headers**

```text
curl -I $url
```

**Cewl**

```text
cewl $url/index.php -m 3 --with-numbers -w cewl.txt
```

**Drupal**

```text
python3 drupwn --version 7.28 --mode enum --target $url

droopescan scan drupal -u $url
```

**Shellshock**

```text
# Check if bash vulnerable to CVE-2014-6271 (bash vulnerable if ‘vulnerable’ in output)
env x='() { :;}; echo vulnerable' bash -c "echo this is a test" 

# Brute force CGI files
gobuster dir -u $url/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x "cgi,sh,pl,py" -s "200,204,301,302,307,403,500" -t 16 -o "tcp_port_protocol_gobuster_shellshock.txt"

wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/CGIs.txt --hc 404 -t 16 $url/cgi-bin/FUZZ 2>&1 | tee "tcp_port_protocol_wfuzz.txt"

Webmin uses cgi files - versions up to 1.700 vulnerable to shellshock (http://www.webmin.com/security.html)
```

### Kerberos (88/tcp, 464/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port --script="banner,krb5-enum-users" -oN "tcp_port_kerberos_nmap.txt" $ip
```

### POP3/POP3S (110/tcp, 995/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port "--script=banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN tcp_port_pop3_nmap.txt $ip
```

### RPC (111/tcp, 135/tcp)

**msrpc/rpcbind**

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port --script=banner,msrpc-enum,rpc-grind,rpcinfo -oN tcp_port_rpc_nmap.txt $ip  
```

**rpcinfo**

```text
# List all registered RPC programs
rpcinfo -p $ip

# Provide compact results
rpcinfo -s $ip
```

**Null session**

```text
rpcclient -U "" -N $ip
    srvinfo
    enumdomusers
    getdompwinfo
    querydominfo
    netshareenum
    netshareenumall
```

### ident (113/tcp)

**Enumerate users services running as**

```text
ident-user-enum $ip 22 25 80 445
```

### NTP (123/udp)

```text
# Run ntp-info NSE script
sudo nmap -sU -p 123 --script ntp-info $ip
```

### NetBIOS-NS (137/udp)

**enum4linux**

```text
enum4linux -a -M -l -d $ip 2>&1 | tee "enum4linux.txt"
```

**nbtscan**

```text
nbtscan -rvh $ip 2>&1 | tee "nbtscan.txt"
```

### SMB (139/tcp, 445/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 445 "--script=banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN tcp_445_smb_nmap.txt $ip
```

**smbmap**

```text
# List share permissions
smbmap -H $ip -P 445 2>&1 | tee -a "smbmap-share-permissions.txt"; smbmap -u null -p "" -H $ip -P 445 2>&1 | tee -a "smbmap-share-permissions.txt"

# List share contents
smbmap -H $ip -P 445 -R 2>&1 | tee -a "smbmap-list-contents.txt"; smbmap -u null -p "" -H $ip -P 445 -R 2>&1 | tee -a "smbmap-list-contents.txt"
```

**enum4linux**

```text
enum4linux -a -M -l -d $ip 2>&1 | tee "enum4linux.txt"
```

**Enumerate Samba version (\*nix)**

```text
# NB: change interface tcpdump listening on
sudo ./smbver.sh $ip 139
```

**Null session**

```text
smbmap -H $ip
smbclient -L //$ip/ -U '' -N
```

**Enumerate shares**

```text
nmap --script smb-enum-shares -p 445 $ip
```

**Connect to wwwroot share (try blank password)**

```text
smbclient \\\\$ip\\wwwroot
```

**Nmap scans for SMB vulnerabilities (NB: can cause DoS)**

```text
# RRAS Service Overflow
# https://docs.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-025
nmap -Pn -sV -p 445 --script="smb-vuln-ms06-025" --script-args="unsafe=1" -oN "tcp_445_smb_ms06-025.txt" $ip

# DNS RPC Service Overflow
# https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-029
nmap -Pn -sV -p 445 --script="smb-vuln-ms07-029" --script-args="unsafe=1" -oN "tcp_445_smb_ms07-029.txt" $ip

# Server Service Vulnerability
# https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067
nmap -Pn -sV -p 445 --script="smb-vuln-ms08-067" --script-args="unsafe=1" -oN "tcp_445_smb_ms08-067.txt" $ip

# Eternalblue
# https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010    
nmap -p 445 --script smb-vuln-ms17-010 -oN "tcp_445_smb_ms08-067.txt" $ip
```

### IMAP/IMAPS (143/tcp, 993/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port "--script=banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN tcp_port_imap_nmap.txt $ip  
```

### SNMP (161/udp)

```text
# Version detection + NSE scripts
sudo nmap -Pn -sU -sV -p 161 --script="banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "udp_161_snmp-nmap.txt" $ip       
```

**Brute force community strings**

```text
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt $ip 2>&1 | tee "udp_161_snmp_onesixtyone.txt"      
```

**snmpwalk**

```text
# Enumerate entire MIB tree
snmpwalk -c public -v1 -t 10 $ip

# Enumerate Windows users
snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25

# Enumerate running Windows processes
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2

# Enumerate open TCP ports
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.6.13.1.3

# Enumerate installed software
snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2
```

**Enumerate SNMP device (places info in readable format)**

```text
snmp-check $ip -c public
```

### LDAP (389/tcp, 3268/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p $port --script="banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_port_ldap_nmap.txt" $ip
```

**enum4linux**

```text
enum4linux -a -M -l -d $ip 2>&1 | tee "enum4linux.txt"
```

### Java RMI (1100/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 1100 --script="banner,rmi-vuln-classloader,rmi-dumpregistry" -oN "tcp_110_rmi_nmap.txt" $ip
```

### MSSQL (1433/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 1433 --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port=1433,mssql.username=sa,mssql.password=sa" -oN "tcp_1433_mssql_nmap.txt" $ip
```

**mssqlclient&#46;py**

```text
# MSSQL shell
mssqlclient.py -db msdb hostname/sa:password@$ip

# List databases
SELECT name FROM master.dbo.sysdatabases

# List tables
SELECT * FROM <database_name>.INFORMATION_SCHEMA.TABLES

# List users and password hashes
SELECT sp.name AS login, sp.type_desc AS login_type, sl.password_hash, sp.create_date, sp.modify_date, CASE WHEN sp.is_disabled = 1 THEN 'Disabled' ELSE 'Enabled' END AS status FROM sys.server_principals sp LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id WHERE sp.type NOT IN ('G', 'R') ORDER BY sp.name   
```

### Oracle TNS listener (1521/tcp)

**tnscmd10g**

```text
tnscmd10g version -h $ip
tnscmd10g status -h $ip
```

### NFS (2049/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 111,2049 --script="banner,(rpcinfo or nfs*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_111_2049_nfs_nmap.txt" $ip
```

**Show mount information**

```text
showmount -e $ip
```

**Mount share**

```text
sudo mount -o rw,vers=2 $ip:/home /mnt

# '-o nolock' used to disable file locking, needed for older NFS servers
sudo mount -o nolock $ip:/home /mnt/
```

### MySQL (3306/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 3306 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_3306_mysql_nmap.txt" $ip
```

**MySQL shell**

```text
mysql --host=$ip -u root -p
```

**MySQL system variables**

```text
SHOW VARIABLES;     
```

**Show privileges granted to current user**

```text
SHOW GRANTS;
```

**Show privileges granted to root user**

```text
# Replace 'password' field with 'authentication_string' if it does not exist
SELECT user,password,create_priv,insert_priv,update_priv,alter_priv,delete_priv,drop_priv FROM mysql.user WHERE user = 'root';
```

**Exact privileges**

```text
SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges;     
```

**Enumerate file privileges (see [here](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) for discussion of file_priv)**

```text
SELECT user FROM mysql.user WHERE file_priv='Y';
```

### RDP (3389/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 3389 --script="banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "tcp_3389_rdp_nmap.txt" $ip
```

### SIP (5060/udp)

**Scans for SIP devices on network**

```text
svmap $ip
```

**Identifies active extensions on PBX**

```text
svwar -m INVITE -e 200-250 $ip
```

### PostgreSQL (5432/tcp)

**Log into postgres remotely**

```text
PGPASSWORD=postgres psql -h $ip -p 5437 -U postgres
```

**List databases**

```text
\list
SELECT datname FROM pg_database;
```

**Use postgres database**

```text
\c postgres
```

**List tables**

```text
\d
```

**Describe table**

```text
\d table
```

**Check if current user superuser (on = yes, off = no)**

```text
SELECT current_setting ('is_superuser');
```

**Get user roles**

```text
\du+
```

**Check user’s privileges over table (pg_shadow)**

```text
SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_name='pg_shadow';
```

**Read file (/etc/passwd)**

```text
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;
```

**Read usernames and password hashes**

```text
# Postgresql password hash format: md5(secret || username) where || denotes string concatenation (remove md5 before cracking hash)
SELECT usename, passwd from pg_shadow;
```

**Check if plpgsql enabled**

```text
# Below result indicates that plpgsql enabled:
# lanname | lanacl
#---------+---------
# plpgsql |            
SELECT lanname,lanacl FROM pg_language WHERE lanname = 'plpgsql'
```

**PostgreSQL config file location**

```text
SHOW config_file;
```

### VNC (5900/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 5900 --script="banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" -oN "tcp_5900_vnc_nmap.txt" $ip
```

### AJP (8009/tcp)

```text
# Version detection + NSE scripts
nmap -Pn -sV -p 8009 -n --script ajp-auth,ajp-headers,ajp-methods,ajp-request -oN tcp_8009_ajp_nmap.txt $ip
```

## Active Directory

**Enumerate users**

```text
net user
net user /domain
net user $domain_user /domain
```

**Enumerate groups**

```text
net group /domain

# Includes domain users that are part of local administrators group
net localgroup administrators
```

**PowerView**

```text
# Import PowerView
PS> Import-Module .\PowerView.ps1

# Get info about current domain
PS> Get-NetDomain

# List members of Domain Admins group
PS> Get-NetGroupMember -GroupName "Domain Admins"

# List all computers in domain
PS> Get-NetComputer

# Enumerate logged-on users
# NB: only lists users logged on to target if we have local administrator privileges on target
PS> Get-NetLoggedon -ComputerName $hostname

# Enumerate active user sessions on servers e.g. file servers or domain controllers
PS> Get-NetSession -ComputerName $hostname

# Enumerate SPNs
PS> Get-NetUser -SPN | select serviceprincipalname
```
