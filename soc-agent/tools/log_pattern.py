import re
from typing import Optional
from models import ToolResult

# MITRE ATT&CK pattern library
# (pattern_name, regex, mitre_id, mitre_name, base_confidence)
PATTERNS = [
    # Brute Force / Credential Access
    # Brute force only flagged with HIGH count (>=10). Low-count auth fails
    # are more often typos or legitimate retries.
    ("brute_force",          re.compile(r"(?:login[_\s]fail|authentication[_\s]fail|invalid[_\s]password|wrong[_\s]password|bad[_\s]credentials|failed[_\s]password)[^\n]{0,150}?(?:\()?\s*(?:1\d|[2-9]\d|\d{3,})\s*(?:attempt|count|time|fail|tr(?:y|ies))s?\b|(?:count|attempt)[s]?[:\s=]+(?:\()?\s*(?:1\d|[2-9]\d|\d{3,})", re.I), "T1110", "Brute Force", 0.85),
    # Low-count failed-auth (1-9 attempts) — explicitly benign / noise
    ("low_count_auth_fail",  re.compile(r"(?:failed[_\s]password|authentication[_\s]fail|invalid[_\s]password|login[_\s]fail)[^\n]{0,120}?(?:\(|\s)(\d)\s*(?:attempt|time|try|tries)s?\b", re.I), "T1110", "Brute Force (low count — likely benign)", 0.15),
    ("repeat_failures",      re.compile(r"repeat\s+\d+\s+times|failed.*repeat|\d+\s+failed\s+attempt", re.I), "T1110", "Brute Force", 0.85),
    # DoS / DDoS
    ("syn_flood",            re.compile(r"(?:syn[_\s]flood|ddos|dos[_\s]attack|\d+[/\s]sec.*syn|syn.*\d+[/\s]sec|(?:drop|block|deny).*flags=syn\b)", re.I), "T1498", "Network Denial of Service", 0.9),
    ("high_packet_rate",     re.compile(r"(?:count|rate|pps)[=:\s]+(\d{4,})", re.I), "T1498", "Network Denial of Service", 0.75),
    # Privilege Escalation
    ("sudoers_add",          re.compile(r"(?:added\s+to\s+(?:group\s+)?sudoers|usermod.*sudo|sudo.*group|wheel\s+group)", re.I), "T1548", "Abuse Elevation Control Mechanism", 0.9),
    ("credential_dump",      re.compile(r"(?:mimikatz|lsass|ntds\.dit|hashdump|sekurlsa)", re.I), "T1003", "OS Credential Dumping", 0.95),
    # Execution
    ("cmd_execution",        re.compile(r"(?:cmd\.exe|command\.com|/bin/sh|/bin/bash)\s", re.I), "T1059", "Command and Scripting Interpreter", 0.8),
    ("powershell_exec",      re.compile(r"powershell(?:\.exe)?\s+(?:-\w+\s+)*(?:-enc|-encodedcommand|-nop|-noprofile|-w\s+hidden)", re.I), "T1059.001", "PowerShell", 0.85),
    ("script_exec",          re.compile(r"(?:wscript|cscript|mshta|regsvr32|rundll32)\.exe", re.I), "T1059.005", "Visual Basic", 0.8),
    # Persistence
    ("scheduled_task",       re.compile(r"(?:schtasks|at\.exe|crontab|systemctl\s+enable)", re.I), "T1053", "Scheduled Task/Job", 0.7),
    # Registry Run key persistence — ONLY when value points to a suspicious
    # path (user-writable / temp / public). Values in Program Files are
    # routinely used by legitimate software (EDR, AV, media players, etc.).
    ("registry_run",         re.compile(r"(?:HKLM|HKCU)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[^\n]*=\s*[\"']?(?:C:\\(?:Users\\Public|Users\\[^\\]+\\AppData|ProgramData|Windows\\Temp|Temp)\\|[A-Z]:\\[^\\]+\\(?:\$Recycle|\$Temp))[^\n\"']*\.(?:exe|dll|bat|ps1|cmd|vbs|js|scr)", re.I), "T1547.001", "Registry Run Keys (suspicious path)", 0.85),
    # Privilege Escalation
    ("sudo_abuse",           re.compile(r"sudo\s+(?:-s|-i|su\b|bash|sh\b)", re.I), "T1548.003", "Sudo and Sudo Caching", 0.7),
    ("setuid",               re.compile(r"chmod\s+(?:[0-9]*[467][0-9]*)\s|setuid|setgid", re.I), "T1548.001", "Setuid and Setgid", 0.75),
    # Defense Evasion
    # Log clearing as anti-forensics. Tightened to Security/Audit log and
    # destructive tools; exclude Application/System log rotations that are
    # followed by a legitimate archive event.
    ("log_cleared",          re.compile(
        r"(?:clearev\b|wevtutil\s+cl\b|auditpol\s+/clear|rm\s+-rf\s+/var/log|"
        r"EventID\s*=\s*1102[^\n]*LogName\s*=\s*Security(?!(?:[^\n]*(?:Log[_\s]?file\s+rotated|Log[_\s]Archive|archived|backup\w*\\)))|"
        r"audit[_\s]log\s+(?:was\s+)?cleared|Security[^\n]*log[^\n]*cleared)",
        re.I), "T1070.001", "Clear Windows Event Logs", 0.88),
    ("icmp_sweep",           re.compile(r"ICMP\s+Echo\s+Request[^\n]*?\d+\.\d+\.\d+\.\d+\s*->\s*\d+\.\d+\.\d+\.\d+-\d+[^\n]*?\(\s*(\d+)\s+hosts?\s+in\s+(\d+)\s*seconds?", re.I), "T1018", "Remote System Discovery", 0.9),
    ("pam_backdoor",         re.compile(r"/etc/pam\.d/\w+[^\n]*?(?:modified|added|inserted|appended)[^\n]*?pam_permit\.so|pam_permit\.so[^\n]*?(?:before|prepend)[^\n]*?pam_unix", re.I), "T1556.003", "Pluggable Authentication Modules", 0.95),
    # C2 beacon — consistent-size request at fixed interval over a long window
    ("beacon_interval",      re.compile(r"(?:avg|average)\s+[\d.]+\s*(?:bytes|KB|MB)\s+every\s+\d+\s*s(?:ec(?:onds?)?)?\s+for\s+[\d.]+\s*(?:h(?:ours?)?|min(?:utes?)?)|POST\s+request[s]?[^\n]{0,40}every\s+\d+\s*s(?:ec(?:onds?)?)?\s+for\s+[\d.]+\s*h", re.I), "T1071", "Application Layer Protocol", 0.92),
    # Cloud instance-metadata theft (IMDS SSRF) — direct HTTP fetch of
    # security-credentials without IMDSv2 token header or SDK context
    ("imds_cred_theft",      re.compile(r"(?=.*169\.254\.169\.254/latest/meta-data/iam/security-credentials)(?!.*(?:X-aws-ec2-metadata-token|IMDSv2|credential-refresher|boto3|aws-sdk|\bSDK\b|AssumeRole|STS\b))", re.I | re.DOTALL), "T1552.005", "Cloud Instance Metadata API", 0.92),
    # Lateral movement: SMB write of executable to remote admin share Temp/AppData
    ("smb_lateral_drop",     re.compile(r"SMB2?[^\n]*(?:Write|Create)[^\n]*\\\\[\d.]+\\(?:[A-Z]+\$|ADMIN\$|IPC\$)\\(?:Windows\\(?:Temp|System32|SysWOW64)|Users\\[^\\]+\\AppData|Users\\Public|ProgramData|Temp)\\[^\\]+\.(?:exe|dll|scr|bat|ps1|vbs|js|sys)", re.I), "T1021.002", "SMB/Windows Admin Shares", 0.9),
    # Scheduled task (EventID 4698) with payload in user-writable / public path = persistence
    ("sched_task_persist",   re.compile(r"EventID[=:\s]*4698[^\n]*Action[=:\s]*[\"']?[A-Z]:\\(?:Users\\Public|Users\\[^\\]+\\AppData|ProgramData|Windows\\Temp|Temp)\\[^\\]+\.(?:exe|bat|cmd|ps1|vbs|js|dll)", re.I), "T1053.005", "Scheduled Task", 0.9),
    # MSBuild LOLBin — invoked from a user-writable path by a non-developer parent
    ("msbuild_lolbin",       re.compile(r"MSBuild\.exe[^\n]{0,200}C:\\Users\\(?:Public|[^\\]+\\(?:AppData|Desktop|Downloads|Documents))[^\n]{0,200}ParentImage\s*=\s*(?:[A-Z]:\\[^\n]*?\\)?(?:explorer\.exe|cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|outlook\.exe|winword\.exe|excel\.exe|mshta\.exe|rundll32\.exe)", re.I), "T1127", "Trusted Developer Utilities Proxy Execution", 0.9),
    # Admin account email rewrite = account takeover precursor (password-reset hijack)
    ("admin_email_takeover", re.compile(r"UPDATE\s+\w*users\w*\s+SET[^\n]{0,120}email\s*=\s*['\"][^'\"]+['\"][^\n]{0,120}WHERE[^\n]*(?:username|user|login|name)\s*=\s*['\"]?(?:admin|administrator|root|superuser)['\"]?", re.I), "T1098", "Account Manipulation", 0.92),
    ("encoded_cmd",          re.compile(r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}", re.I), "T1027", "Obfuscated Files or Information", 0.85),
    # Discovery
    ("network_scan",         re.compile(r"(?:nmap|masscan|zmap|portscan|port[_\s]scan)", re.I), "T1046", "Network Service Discovery", 0.8),
    ("system_info",          re.compile(r"(?:whoami|hostname|ipconfig|ifconfig|uname\s+-a|systeminfo)", re.I), "T1082", "System Information Discovery", 0.65),
    # Lateral Movement
    ("lateral_smb",          re.compile(r"(?:psexec|wmiexec|pass[_\s]the[_\s]hash|pth\b|smb.*lateral)", re.I), "T1021.002", "SMB/Windows Admin Shares", 0.85),
    ("rdp_lateral",          re.compile(r"(?:rdp|remote[_\s]desktop|mstsc).*(?:new|connect|lateral)", re.I), "T1021.001", "Remote Desktop Protocol", 0.7),
    # Exfiltration
    ("large_upload",         re.compile(r"(?:sent|upload|egress|outbound)[^\n]*?(\d+(?:\.\d+)?\s*(?:GB|MB))", re.I), "T1041", "Exfiltration Over C2 Channel", 0.75),
    ("dns_exfil",            re.compile(r"dns.*(?:tunnel|exfil|data)|(?:base64|hex).*dns", re.I), "T1048.003", "Exfiltration Over Alternative Protocol", 0.8),
    # Command & Control
    ("c2_beacon",            re.compile(r"(?:beacon|heartbeat|check[_\s]in|c2[_\s]server|command[_\s]and[_\s]control|cobalt[_\s]strike|et[_\s]trojan|ids[_\s]alert.*trojan)", re.I), "T1071", "Application Layer Protocol", 0.95),
    ("tor_usage",            re.compile(r"(?:\.onion|tor[_\s]exit|tor[_\s]node|torproject)", re.I), "T1090.003", "Multi-hop Proxy", 0.85),
    # Impossible Travel
    ("impossible_travel",    re.compile(r"(?:impossible[_\s]travel|login.*different.*location|prev.*location|location.*mismatch)", re.I), "T1078", "Valid Accounts", 0.85),
    # DNS Tunneling
    ("dns_tunnel_subdomain", re.compile(r"dns.*(?:TXT|tunnel|datachunk|chunk\d+)|qname.*\d{4,}", re.I), "T1048.003", "Exfiltration Over Alternative Protocol", 0.85),
    # Web Attacks
    ("sql_injection",        re.compile(r"(?:'[_\s]*or[_\s]*'|union[_\s]+select|drop[_\s]+table|1[_\s]*=[_\s]*1|%27|%3d|sqlmap)", re.I), "T1190", "Exploit Public-Facing Application", 0.9),
    ("xss",                  re.compile(r"(?:<script|javascript:|onerror=|onload=|alert\(|document\.cookie)", re.I), "T1190", "Exploit Public-Facing Application", 0.85),
    ("path_traversal",       re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%252e)", re.I), "T1190", "Exploit Public-Facing Application", 0.8),
    ("log4shell",            re.compile(r"\$\{jndi:", re.I), "T1190", "Exploit Public-Facing Application", 0.99),
    # Impact
    ("ransomware_sig",       re.compile(r"(?:\.locked|\.encrypted|ransom|your[_\s]files[_\s]are|decrypt[_\s]instructions)", re.I), "T1486", "Data Encrypted for Impact", 0.9),
    ("data_destruction",     re.compile(r"(?:dd[_\s]+if=/dev/zero|rm[_\s]+-rf[_\s]+/|format[_\s]+c:|wipe)", re.I), "T1485", "Data Destruction", 0.9),
    # LOLBin abuse
    ("certutil_lolbin",      re.compile(r"certutil.*(?:-urlcache|-decode|-encode|http|ftp|urlcache)", re.I), "T1105", "Ingress Tool Transfer", 0.90),
    ("lolbin_download",      re.compile(r"(?:bitsadmin.*(?:http|/transfer)|mshta.*http|regsvr32.*http|wmic.*http)", re.I), "T1105", "Ingress Tool Transfer", 0.85),
    # Kerberos attacks
    ("golden_ticket",        re.compile(r"(?:krbtgt|golden[_\s]ticket|ticket.*lifetime.*\d{4,}[h\s]|RC4_HMAC.*kerberos|kerberos.*RC4_HMAC|ticketlifetime=\d{4,})", re.I), "T1558.001", "Golden Ticket", 0.95),
    ("kerberoasting",        re.compile(r"(?:kerberoast|EventID.*4769.*RC4|servicename.*krbtgt|spn.*ticket.*rc4)", re.I), "T1558.003", "Kerberoasting", 0.90),
    # Data staging
    ("data_staging",         re.compile(r"(?:7z|winrar|rar\.exe|zip).*(?:-p|-password|password).*(?:confidential|sensitive|finance|salary|hr_|secret|private|legal|executive)", re.I), "T1074.001", "Local Data Staging", 0.90),
    ("data_staging_path",    re.compile(r"(?:7z|winrar|rar\.exe).*(?:C:\\Confidential|C:\\Finance|C:\\HR|C:\\Legal|C:\\Executive|\\AppData\\Local\\Temp\\archive)", re.I), "T1074.001", "Local Data Staging", 0.85),
    # Supply chain
    ("supply_chain",         re.compile(r"(?:hash.*mismatch|sha256.*differ|checksum.*fail|signature.*invalid|postinstall.*(?:spawn|connect|exec)|hash.*differ.*vendor)", re.I), "T1195.002", "Compromise Software Supply Chain", 0.90),
    # Steganographic exfiltration
    ("stego_exfil",          re.compile(r"(?:entropy[=:\s]+[7-9]\.\d+|high[_\s]entropy.*upload|upload.*entropy[=:\s]+[7-9])", re.I), "T1048", "Exfiltration Over Alternative Protocol", 0.85),
    # Credential stuffing
    ("credential_stuffing",  re.compile(r"(?:source[_\s]ips?[:\s]+[\d.,\s]{10,}|multiple.*source.*ip|usernames.*tried.*(?:admin|root|test)|attempt.*over.*\d+.*hours?.*username)", re.I), "T1110.004", "Credential Stuffing", 0.85),
    # Off-hours admin RDP from flagged host
    ("off_hours_admin_rdp",  re.compile(r"LogonType=10.*(?:administrator|admin).*(?:flagged|suspicious.*prior|prior.*suspicious|\b[12]:[0-5]\d\s*[Aa][Mm]\b|\b[34]:[0-5]\d\s*[Aa][Mm]\b)|(?:flagged|suspicious.*prior).*LogonType=10.*(?:administrator|admin)", re.I), "T1021.001", "Remote Desktop Protocol", 0.90),
    # Unauthorized data access
    ("unauthorized_data_access", re.compile(r"(?:First_time_access|first[_\s]time[_\s]access).*(?:Confidential|Executive|Salary|Finance|HR|Legal|sensitive)|(?:Confidential|Executive|Salary|Finance|HR|Legal).*(?:First_time_access|first[_\s]time[_\s]access)", re.I), "T1213", "Data from Information Repositories", 0.85),
    # Temp scheduled tasks
    ("temp_sched_task",      re.compile(r"(?:schtasks|task_scheduler|task\s+').*(?:\\temp\\|\\windows\\temp|appdata.*temp|/tmp/)", re.I), "T1053.005", "Scheduled Task", 0.90),
    # ─── Additional MITRE signatures ───
    # SSRF via webhook / notify / callback API pointing to an internal admin URL
    ("ssrf_webhook",         re.compile(r"POST\s+/[\w/]*(?:webhook|notify|callback|proxy|fetch|preview)\b[^\n]{0,300}\"url\"\s*:\s*\"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|localhost)[^\"]*(?:/admin|/metadata|/internal|/api|/secret|:\d{2,5}/)", re.I), "T1190", "Exploit Public-Facing Application (SSRF)", 0.92),
    # ICMP covert-channel / tunnel: large-payload echo replies repeated
    ("icmp_tunnel",          re.compile(r"ICMP[^\n]{0,300}Payload\s*=\s*(?:[5-9]\d{2}|\d{4,})\s*bytes[^\n]{0,300}Pattern\s*:\s*(?:[3-9]\d|\d{3,})\s*ICMP\s*packets\s*with\s*>\s*\d+\s*byte\s*payloads", re.I), "T1095", "Non-Application Layer Protocol (ICMP Tunnel)", 0.93),
    # TCP SYN port scan — many ports in a very short window
    ("tcp_syn_portscan",     re.compile(r"FIREWALL[^\n]{0,150}TCP\s*SYN[^\n]{0,300}\(\s*(?:[5-9]|\d{2,})\s*ports?\s*in\s*[1-5]\s*s", re.I), "T1046", "Network Service Discovery", 0.9),
    # Command / shell injection via URL parameter
    ("cmd_injection_url",    re.compile(r"(?:GET|POST)\s+[^\s]*\?[^\s]*(?:\?|&)(?:cmd|exec|command|system|shell|input)\s*=\s*(?:[;|&`]|%3[Bb]|%7[Cc]|%26|\$\()[^\s]*(?:cat|ls|id|whoami|uname|/etc/passwd|/etc/shadow|bash|sh\s)", re.I), "T1059.004", "Unix Shell (CGI Cmd Injection)", 0.93),
    # Cloud privilege escalation — admin role/policy grant
    ("cloud_priv_esc",       re.compile(r"(?:eventName[\"'\s:=]+(?:AssumeRole|CreateAccessKey|AttachUserPolicy|AttachRolePolicy|CreateUser|PutUserPolicy|PutRolePolicy|CreateLoginProfile))[^\n]{0,400}(?:Admin(?:istrator)?(?:Full)?Access|AdminPolicy|arn:aws:iam::(?:aws|)?:policy/Admin)", re.I), "T1098", "Account Manipulation (Cloud)", 0.93),
    # S3 bucket takeover — public Principal
    ("bucket_public",        re.compile(r"PutBucketPolicy[^\n]{0,400}\"Effect\"\s*:\s*\"Allow\"[^\n]{0,200}\"Principal\"\s*:\s*(?:\"\\?\*\\?\"|\{[^}]*\"AWS\"\s*:\s*\"\\?\*\\?\")", re.I), "T1530", "Data from Cloud Storage Object", 0.95),
    # Impossible-travel signature in log body
    ("impossible_travel_ct", re.compile(r"(?:ConsoleLogin|Login|Authentication)[^\n]{0,400}(?:sourceIPAddress|src_ip)[^\n]{0,200}prevEvent[^\n]{0,400}location", re.I), "T1078", "Valid Accounts", 0.91),
    # PowerShell profile.ps1 persistence
    ("ps_profile_persist",   re.compile(r"FileCreate[^\n]*(?:\\WindowsPowerShell\\[^\\]+\\profile\.ps1|\\Microsoft\\WindowsPowerShell\\profile\.ps1)[^\n]*Process\s*:\s*(?:notepad\.exe|cmd\.exe|mshta|rundll32|certutil|powershell\.exe[^\n]*-enc)", re.I), "T1546.013", "PowerShell Profile", 0.93),
    # WinRM beacon — port 5985 small packets at fixed interval over hours
    ("winrm_beacon",         re.compile(r"(?:DPort|Port)\s*=\s*5985\b[^\n]{0,200}(?:Interval\s*=\s*\d+\s*s|every\s+\d+\s*s)[^\n]{0,200}(?:Duration|for)\s*[=:]?\s*\d+\s*(?:h|hour|m(?:in)?)", re.I), "T1021.006", "Windows Remote Management", 0.92),
    # WPAD / LLMNR-NBT-NS poisoning
    ("wpad_poison",          re.compile(r"DNS\s+Query[^\n]*QName\s*=\s*wpad\b[^\n]*(?:NXDOMAIN|non-(?:authoritative|DHCP)|unexpected\s+host)|wpad\.local[^\n]{0,200}(?:non-DHCP\s+server|resolved\s+to\s+(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.))", re.I), "T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", 0.92),
    # Kernel module loaded from suspicious path (rootkit)
    ("kernel_mod_suspicious",re.compile(r"(?:finit_module|init_module|insmod|modprobe)[^\n]{0,200}(?:exe|comm|path)\s*=\s*[\"']?(?:/tmp/|/dev/shm/|/var/tmp/|/run/user/|/home/[^/]+/\.[^/]+/|/(?!lib/modules|usr/lib/modules)\w+/[^\"'\n]*\.ko\b)", re.I), "T1014", "Rootkit (Kernel Module)", 0.95),
    # Ptrace process injection
    ("ptrace_inject",        re.compile(r"ptrace[^\n]*PTRACE_(?:ATTACH|SEIZE|POKE\w*)[^\n]*pid\s*=\s*(?:1\b|\d{1,3}\b)[^\n]*uid\s*=\s*(?:[1-9]\d{2,}|[1-9]\d{3,})", re.I), "T1055.008", "Process Injection: Ptrace", 0.92),
    # Database code-execution via native features
    ("db_code_exec",         re.compile(r"\bLOAD\s+[\"']?\$libdir\b|\bLOAD\s+(?:DATA\s+LOCAL\s+)?[\"']/[^'\"\n]{0,200}\.so\b|\bCOPY\s+\w+\s+FROM\s+PROGRAM\s+['\"]|\bCREATE\s+FUNCTION\s+[^\n]{0,200}(?:AS\s+)?['\"]?\$libdir|\bsys_exec\s*\(|\bsys_eval\s*\(|\bSELECT\s+.*\bxp_cmdshell\s*\(|\bALTER\s+(?:USER|ROLE)\s+\w+\s+(?:SUPERUSER|WITH\s+SUPERUSER|BYPASSRLS|CREATEROLE|REPLICATION)|\bGRANT\s+(?:ALL|SUPERUSER|ROLE\s+\w+|sa\b|admin)\s+(?:ON|TO)\b", re.I), "T1059", "DB-Native Code Execution", 0.93),
    # Outbound to external IP on known-malicious / C2 port
    ("external_c2_port",     re.compile(r"(?:FIREWALL|conn|connection|TCP|UDP)[^\n]{0,120}(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\n]{0,20}(?:->|to|→)\s*(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)\d+\.\d+\.\d+\.\d+\s*:\s*(?:4444|6666|6667|9001|9030|31337|50050|1337|5555|8888|12345|54321|7777)\b", re.I), "T1071", "Application Layer Protocol (Malicious Port)", 0.93),
    # XML-RPC remote code execution
    ("xmlrpc_rce",           re.compile(r"POST\s+/[\w/]*xmlrpc\.php[^\n]{0,300}<methodCall>[^\n]*<methodName>\s*(?:system\.exec|system\.shell|exec\.exec|shell\.exec|pingback\.ping)\s*</methodName>", re.I), "T1190", "Exploit Public-Facing Application (XML-RPC)", 0.93),
    # Hidden admin account creation
    ("hidden_admin_account", re.compile(r"EventID[=:\s]*4720[^\n]*Target(?:User)?Name[=:\s]*\w+\$[^\n]{0,300}Groups[=:\s]*[^\n]*Administrators[^\n]{0,200}AccountType[=:\s]*Hidden|AccountType[=:\s]*Hidden[^\n]{0,200}Groups[=:\s]*[^\n]*Administrators", re.I), "T1136.001", "Create Account: Local Account", 0.94),
    # Suspicious service install (EventID 7045) from non-standard path
    ("malicious_service",    re.compile(r"EventID[=:\s]*7045[^\n]*ImagePath[=:\s]*[\"']?[A-Z]:\\(?:ProgramData|Users\\Public|Users\\[^\\]+\\AppData|Windows\\Temp|Temp)\\", re.I), "T1543.003", "Create or Modify System Process: Windows Service", 0.93),
    # Kernel driver install via sc.exe (rootkit)
    ("kernel_driver_install",re.compile(r"sc\.exe[^\n]{0,200}\\drivers\\[^\n]*\.sys|FileCreate[^\n]*\\System32\\drivers\\[^\n]*\.sys[^\n]*sc\.exe|sc\.exe[^\n]*(?:create|config)[^\n]*type=\s*kernel", re.I), "T1014", "Rootkit (Driver Install)", 0.95),
    # Mass unbounded SELECT with huge row count
    ("mass_select",          re.compile(r"SELECT\s+\*\s+FROM\s+\w+(?:\s*;|\s*--)[^\n]{0,80}(?:returned\s+(?:\d{1,3},?){2,}\d+\s+rows|rows[=:\s]+(?:\d{1,3},?){2,}\d+|(?:\d{1,3},?){2,}\d+\s+rows)", re.I), "T1005", "Data from Local System (Bulk SELECT)", 0.88),
    # Advanced SQL injection — AND/OR SELECT, UNION, information_schema, DB proc abuse
    ("sql_injection_adv",    re.compile(r"(?:'\s*(?:AND|OR)\s+\(?\s*SELECT|\bUNION\s+(?:ALL\s+)?SELECT\b|information_schema|pg_catalog|sys\.databases|\bexec\s*\(\s*(?:@|sp_|xp_))", re.I), "T1190", "Exploit Public-Facing Application (Advanced SQLi)", 0.93),
    # AMSI bypass — classic string-split / reflection / AmsiInitFailed technique
    ("amsi_bypass",          re.compile(r"(?:AmsiUtils|amsiInitFailed|amsiContext|amsiSession)|\[Ref\]\.Assembly\.GetType\s*\(\s*['\"]System\.Management\.Automation\.(?:Am['\"]?\s*\+\s*['\"]?si\w+|Amsi\w+)", re.I), "T1562.001", "Disable or Modify Tools (AMSI Bypass)", 0.93),
]

# ── Benign indicators ──────────────────────────────────────────────────────
# These patterns explicitly mark activity as known-legitimate. Separate from
# attack signatures so the tool reports both dimensions. The coordinator /
# subagent can use benign_indicators to suppress false positives.
BENIGN_INDICATORS = [
    # Sysadmin sudo — read-only log / config viewing
    ("sudo_read_only",   re.compile(r"sudo[^\n]{0,120}/(?:bin|usr/bin|usr/sbin)/(?:tail\b|cat\s+/(?:etc|var|proc)|less\b|more\b|head\b|grep\b|journalctl\b|dmesg\b|w\b|who\b|last\b|uptime\b|ps\s+(?:aux|ef)|free\b|df\b|du\b|lsof\b|ss\s|netstat|iostat|vmstat|top\b|htop\b)", re.I), "routine sysadmin read"),
    # Sysadmin sudo — service management
    ("sudo_service_mgmt",re.compile(r"sudo[^\n]{0,120}/(?:bin|usr/bin|usr/sbin|sbin)/(?:systemctl|service)\s+(?:restart|reload|status|start|stop)\s+(?:nginx|apache2?|httpd|postgres(?:ql)?|mysql|mariadb|redis|docker|kubelet|containerd|sshd|cron|rsyslog|fail2ban|networking|ntp|chronyd)", re.I), "routine service restart"),
    # DB backup dump
    ("db_backup_dump",   re.compile(r"sudo[^\n]{0,200}(?:pg_dump|mysqldump|mongodump|redis-cli\s+save)\b[^\n]{0,120}-f\s+/(?:var|opt|backups?|mnt)", re.I), "routine database backup"),
    # Internal ELK / SIEM traffic — known ports
    ("internal_elk_traffic", re.compile(r"NetFlow[^\n]*Src\s*=\s*(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\n]{0,100}Dst\s*=\s*(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\n]{0,120}D?Port\s*=\s*(?:9200|9300|5601|5044|5140|8089|8088|8200|9093|9094|9095|2049|3306|5432|5984|6379|27017|11211)", re.I), "internal ELK/SIEM/DB traffic"),
    # SMB read of departmental documents
    ("smb_doc_read",     re.compile(r"SMB2?\s*:\s*Read\s+Request\s+File\s*:\s*\\\\[\w.-]+\\(?:HR|Legal|IT|Finance|Marketing|Sales|Engineering|Policies|Training|Handbook|Runbooks|Benefits|Onboarding|Procedures|Documentation|Executive|Board|Leadership|C[_\s-]*Suite|Boardroom|Shared|Public|Accounting|Operations|Support|Product|Research|R&D|QA|Company|Corporate|General|Common|Archive|Templates|Projects)[^\n]{0,200}\.(?:pdf|docx?|pptx?|xlsx?|txt|md|csv)", re.I), "departmental document read"),
    # VPN session start
    ("vpn_session_start",re.compile(r"(?:CSCO_VPN|AnyConnect|GlobalProtect|FortiClient|OpenVPN|Pulse(?:\s+Secure)?|PAN[_\s]GP|SSL[_\s]?VPN|Cisco\s+ASA)[^\n]{0,200}(?:Session\s+started|Login\s+succeeded|Connection\s+established|authenticated)", re.I), "VPN session start"),
    # Certbot / openssl lifecycle
    ("cert_lifecycle",   re.compile(r"certbot\b[^\n]{0,200}(?:renewed|renewal|Certificate renewed|Renewal successful)|openssl\s+req\s+-new[^\n]{0,200}-key\s+/etc/ssl/", re.I), "certificate renewal"),
    # Security product self-write
    ("security_product_write", re.compile(r"FileCreate[^\n]*Target(?:File)?name\s*=\s*[\"']?C:\\(?:ProgramData|Program\s+Files(?:\s*\(x86\))?)\\(?:Sophos|CrowdStrike|SentinelOne|Defender|Symantec|Norton|McAfee|Trend\s*Micro|BitDefender|Kaspersky|ESET|Carbon\s*Black|Cylance|Tanium|Microsoft|Windows\s*Defender|Splunk\w*|DataDog|Dynatrace|NewRelic|Elastic\w*|Filebeat|Winlogbeat|Logstash|NXLog|Wazuh|OSSEC|Snare)", re.I), "security product self-write"),
    # Enterprise management / EDR inventory scan
    ("mgmt_agent_scan",  re.compile(r"(?:bcdedit\s+/enum|wmic\s+(?:product|service|process|computersystem|os|bios)\s+(?:get|list)|systeminfo\b|ipconfig\b|hostname\b)[^\n]{0,300}ParentImage\s*=\s*[^\n]*(?:ManageEngine|SCCM|CcmExec|SolarWinds|Ivanti|Tanium|Qualys|Rapid7|Lansweeper|PDQ|Kaseya|Crowdstrike|SentinelOne|Defender|Carbon\s*Black|Intune|Jamf|Chef|Puppet|Ansible|Scanner|Agent)", re.I), "management agent inventory"),
    # Benign Docker container lifecycle
    ("container_benign", re.compile(r"(?:docker|containerd|podman|kubelet)\[?\d*\]?\s*:?\s*Container\s+(?:started|created|launched|stopped|restarted|removed|killed|exited)[^\n]{0,200}(?:status\s*=\s*(?:exited\s*\(\s*0\s*\)|stopped|completed|succeeded)|image\s*=\s*(?:\w[\w/.-]*/)?(?:prometheus|grafana|nginx|apache|httpd|postgres(?:ql)?|mysql|mariadb|redis|mongodb|elasticsearch|kibana))", re.I), "routine container lifecycle"),
    # PowerShell read-only reporting
    ("ps_read_only",     re.compile(r"(?:Get-ADUser|Get-ADComputer|Get-ADGroup|Get-Service|Get-Process|Get-EventLog|Get-WinEvent|Get-ChildItem|Get-Item|Get-Mailbox|Get-LocalUser|Get-LocalGroupMember|Get-NetAdapter|Get-WmiObject|Get-CimInstance|Get-HotFix)[^\n]{0,400}(?:\||Export-Csv|Out-File|ConvertTo-(?:Csv|Json|Html)|Format-(?:Table|List))", re.I), "PowerShell read-only reporting"),
    # Security product Run-key auto-start (AV/EDR/Splunk/etc.)
    ("security_product_runkey", re.compile(r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run[^\n]{0,120}(?:CrowdStrike|SentinelOne|Defender|Symantec|McAfee|Sophos|BitDefender|Kaspersky|ESET|Carbon\s*Black|Cylance|Tanium|Qualys|Rapid7|Splunk|SolarWinds|Zabbix|Datadog|NewRelic|Dynatrace|SCCM|Intune|ManageEngine|Wazuh|OSSEC)", re.I), "security product auto-start"),
]


class LogPatternResult(ToolResult):
    tool_name: str = "log_pattern_analyzer"
    matched_patterns: list[dict] = []
    anomaly_score: float = 0.0
    temporal_pattern: Optional[str] = None
    failure_count: Optional[int] = None
    benign_indicators: list[str] = []  # known-legitimate patterns found
    top_keywords: list[str] = []


def _detect_temporal_pattern(log: str) -> Optional[str]:
    counts = re.findall(r"(?:count|attempt|fail)[s]?[:\s]+(\d+)", log, re.I)
    if counts:
        n = int(counts[0])
        if n >= 100:
            return "burst"
        elif n >= 10:
            return "slow_low"
        elif n == 1:
            return "single_spike"
    return "normal"


def _extract_top_keywords(log: str) -> list[str]:
    keywords = []
    for kw in ["password", "admin", "root", "exec", "download", "upload",
               "connect", "login", "shell", "script", "payload", "beacon"]:
        if kw in log.lower():
            keywords.append(kw)
    return keywords[:5]


def log_pattern_analyzer(log_payload: str, log_type: str = "generic") -> LogPatternResult:
    """Analyze log entries for known attack signatures and MITRE ATT&CK patterns."""
    result = LogPatternResult(data_source="local")
    matched = []
    max_confidence = 0.0

    for name, pattern, mitre_id, mitre_name, base_conf in PATTERNS:
        if pattern.search(log_payload):
            matched.append({
                "pattern": name,
                "mitre_id": mitre_id,
                "mitre_name": mitre_name,
                "confidence": base_conf,
            })
            max_confidence = max(max_confidence, base_conf)

    # Detect benign-indicator patterns; if present, they both report the
    # context and dampen the anomaly score.
    benign_hits: list[str] = []
    for bname, bpattern, blabel in BENIGN_INDICATORS:
        if bpattern.search(log_payload):
            benign_hits.append(blabel)
    result.benign_indicators = benign_hits

    result.matched_patterns = matched
    base_score = (
        min(max_confidence + (len(matched) - 1) * 0.05, 1.0) if matched else 0.0
    )
    # If benign context found but only weak attack matches, dampen score
    if benign_hits and max_confidence < 0.85:
        base_score = max(0.0, base_score - 0.5)
    result.anomaly_score = round(base_score, 2)
    result.temporal_pattern = _detect_temporal_pattern(log_payload)
    result.top_keywords = _extract_top_keywords(log_payload)

    counts = re.findall(r"(?:count|fail)[s]?[:\s]+(\d+)", log_payload, re.I)
    if counts:
        result.failure_count = int(counts[0])

    return result
