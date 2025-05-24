# Table of Contents

1. 🔍 [Threat Hunting Scope](#threat-hunting-scope)
2. ⏳ [Timeline Summary and Findings](#timeline-summary-and-findings)
3. ✅ [Investigation Conclusion](#investigation-conclusion)
4. 🛡️ [Relevant MITRE ATT@CK TTPs](#relevant-mitre-attck-ttps)
5. 📈 [Response and Mitigation Steps](#response-and-mitigation-steps)

# Threat Hunting Scope

**Objective:** As part of routine maintenance, the security team is responsible for examining virtual machines (VMs) within the shared services cluster (e.g., DNS, Domain Services, DHCP) that may have been inadvertently exposed to the public internet. The aim is to detect any misconfigured VMs and investigate potential brute-force login attempts or successful logins from external sources.

**Activity:** While these devices were unknowingly accessible online, there is a risk that unauthorised individuals may have successfully brute-forced their way into some of them. This is particularly concerning as certain older devices lack account lockout settings to prevent excessive failed login attempts.

# Timeline Summary and Findings

The initial step is to determine the duration of the machine’s exposure to the internet.

Windows-Target-1 has been publicly accessible for several days.

<img src="https://i.imgur.com/ulbl7Yg.png">

**KQL Query Used:**

```
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
Last internet facing time: 2025-03-31T11:10:18.1999458Z 
```

Several malicious actors have been identified attempting to gain access to the target machine. We have isolated the two most active remote IP addresses trying to connect to our system, which has been exposed to the internet for a prolonged period.

---

### IP in Question 1: 178.20.129.235

<img src="https://i.imgur.com/0YALYxW.png">

This IP address has attempted to log in to our target machine 119 times over the past 30 days. An alert has already been raised for this IP, titled "Unusual Number of Failed Sign-In Attempts."

Further investigation of the IP:

<img src="https://i.imgur.com/WXM9GWI.png">

This IP address, originating from Russia, has been identified as malicious by eight different vendors.

### IP in Question 2:  159.89.179.242

No alerts have been generated for this second IP address, which ranks second in the number of logon attempts. Consequently, we will conduct further investigation using VirusTotal to obtain additional information about it.

<img src="https://i.imgur.com/AY5dp6V.png">

This IP address, originating from the United States, has been identified as malicious by six different vendors.

--- 

Following the detection of multiple login attempts from malicious sources targeting our machine, I will identify the top 10 IP addresses with the highest number of login attempts over the past 30 days. Subsequently, I will execute a KQL query to determine whether any of these IPs successfully accessed the machine.

<img src="https://i.imgur.com/ttspVmQ.png">

**KQL Query Used:**

```
let RemoteIPsInQuestion = dynamic(["178.20.129.235", "159.89.179.242", "128.1.44.9", "88.214.25.74", "194.0.234.17", "83.118.125.238", "185.7.214.14", "185.42.12.59", "216.66.67.107", "185.42.12.79"]);
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess"
| where RemoteIP in (RemoteIPsInQuestion)
| summarize SuccessfulLogins = count() by RemoteIP, DeviceName, ActionType
| order by SuccessfulLogins desc
```


The IPs and their respective failed login counts are:

1.	178.20.129.235 - 119 attempts
2.	159.89.179.242 - 115 attempts
3.	128.1.44.9 - 97 attempts
4.	88.214.25.74 - 64 attempts
5.	194.0.234.17 - 64 attempts
6.	83.118.125.238 - 57 attempts
7.	185.7.214.14 - 55 attempts
8.	185.42.12.59 - 55 attempts
9.	216.66.67.107 - 52 attempts
10.	185.42.12.79 - 51 attempts


There have been no successful logon attempts from the top 10 remote IP addresses examined.

---

<img src="https://i.imgur.com/47ooEvB.png">

**KQL Query Used:**

```
DeviceLogonEvents
| where Timestamp >= ago(30d)
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess"
| summarize SuccessfulLogins = count() by AccountName
| order by SuccessfulLogins desc
```

I have identified all accounts that have successfully logged into the target machine, totalling seven distinct users who have accessed it.

---

I will execute the following query to compile a list of IP addresses that accessed the system using the seven specific accounts identified earlier.

<img src="https://i.imgur.com/BdFN7UO.png">

**KQL Query Used:**

```
DeviceLogonEvents
| where Timestamp >= ago(30d)
| where DeviceName == "windows-target-1"
| where ActionType == "LogonSuccess"
| where AccountName in ("labuser", "dwm-2", "labuser1", "dwm-1", "umfd-2", "umfd-1", "umfd-0")
| summarize LoginCount = count() by RemoteIP, AccountName
| order by LoginCount desc
```

I’ve reviewed all the IP addresses obtained from the previous query and compared them with the top 10 IP addresses responsible for the highest number of login attempts over the past 30 days. No matches were found. Upon further investigation, I confirmed that all IPs associated with successful logins across the seven accounts originated from legitimate traffic.

--- 

# Investigation Conclusion

Through the machine was expose to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorised access from the legitimate accounts linked to the machine. 

# Relevant MITRE ATT@CK TTPS

- T1190: Exploit Public-Facing Application (Machine was internet-facing for several days)
- T1110: Brute Force (Multiple failed logon attempts detected)
- T1071: Application Layer Protocol (Malicious actors attempting remote access)
- T1078: Valid Accounts (Verification of legitimate logins)
- T1040: Network Sniffing (Checking for unauthorised access attempts)

# Response and Mitigation Steps

1. Enable Multi-Factor Authentication (MFA) for all accounts to prevent unauthorized access.
2. Implement account lockout policies after a set number of failed login attempts.
3. Integrate alerts for unusual login patterns and failed attempts from foreign IPs.
4. Block known malicious IPs* or apply geo-blocking for regions irrelevant to your operations.
5. Review firewall rules** and limit unnecessary internet-facing services to reduce exposure.
6. Conduct regular log reviews** to detect anomalies, even if no successful logins occurred.
7. Enable automated IP blacklisting** based on threat intelligence feeds.


