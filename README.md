<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# 🛡️ Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/dasare/ThreatHuntingProject/blob/main/threat-hunting-scenario.md)

## 💻 Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## 🎯 Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### 🧩 High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## 🧪 Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched and reviewed the DeviceFileEvents table for any file that included the string “tor” in its name and found what looks like the user “dasare” downloaded a tor installer. This resulted in many tor-related files being copied to the desktop and creating a file called “tor-shopping-list.txt” on the desktop. These events began at: 2025-05-14T22:40:24.677187Z

**I used the following query to locate the events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName  == "dasare"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-14T22:40:24.677187Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="868" alt="image" src="https://github.com/user-attachments/assets/1b51016a-6784-42da-9f43-386da69c153d" />

---

### 2. Searched the `DeviceProcessEvents` Table

I reviewed the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.1.exe /S”. After reviewing the logs returned at 2025-05-14T22:44:00.8822272Z, an employee on the “threat-hunt-lab” device ran the file “tor-browser-windows-x86_64-portable-14.5.1.exe /S” from their Downloads folder, by using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine  contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1074" alt="image" src="https://github.com/user-attachments/assets/f98a931e-aff8-4fd7-8dd0-2448ab611383" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I reviewed the DeviceProcessEvents table for any evidence that user “dasare” opened and accessed the Tor browser. I observed evidence that the user did open it at: 2025-05-14T22:44:42.493119Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**I used the following query to locate the event:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName  has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```

<img width="1244" alt="image" src="https://github.com/user-attachments/assets/452ce4bd-5d7f-4571-af85-17611e6b066d" />

---

### 4. 🌐 Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I reviewed the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-05-14T22:45:27.7040346Z, an employee on the “threat-hunt-lab” device successfully esablished a connection to the remote IP address 194.147.140.107 on port 443. This the connection was established by the process tor.exe, located in the following folder: c:\users\dasare\desktop\tor browser\browser\torbrowser\tor\tor.exe. I noticed additional connections over port 9150, one successful and the other failed.

**I used the following query to locate the event:**

```kql
DeviceNetworkEvents
| where DeviceName  == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where RemotePort  in ("20", "443", "9001", "9004", "9030", "9031", "9040", "9050", "9051", "9150", "9151")
| project  Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```

<img width="1224" alt="image" src="https://github.com/user-attachments/assets/12694079-c6be-484f-b962-7964cf258aa7" />



---

## Chronological Event Timeline 

### 1. 💻 Tor Browser Silent Installation Command Executed

- **Timestamp:** `2025-05-14T22:44:00.8822272Z`
- **Event:** User **dasare** executed a silent install of the Tor browser.
- **Action Type:** **Process execution**
- **ProcessCommandLine:**
  ```text
  C:\Users\dasare\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe /S
  ```
- **Details:** The `/S` flag confirms a silent install, requiring no user interaction. The Tor installer was run directly from the **Downloads** folder.

---

### 2. 🗂️ Tor Files and Custom Text File Created on Desktop

- **Start Timestamp:** `2025-05-14T22:40:24.677187Z` (preceding the install execution — likely unpacking or copying)
- **Event:** Multiple files with “tor” in their names were created or moved to the desktop.
- **Action Type:** **File created/copied**
- **Notable File:**
  ```text
  C:\Users\dasare\Desktop\tor-shopping-list.txt
  ```
- **Details:** This may indicate intentional planning or tracking by the user, such as logging sites or items related to Tor usage. Additional Tor binary and config files were also deposited in:
  ```text
  C:\Users\dasare\Desktop\Tor Browser\
  ```

---

### 3. 🚀 Tor Browser and Associated Processes Launched

- **Timestamp:** `2025-05-14T22:44:42.493119Z`
- **Event:** Tor Browser launched successfully by user **dasare**. Subsequent processes associated with the Tor browser such as `firefox.exe` and `tor.exe` were also created.
- **Action Type:** **Process execution of Tor browser-related executables detected**
- **Processes Observed:**
  - `firefox.exe`
  - `tor.exe`
  - `tor-browser.exe`
- **Paths Observed:**
  ```text
  C:\Users\dasare\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe  
  C:\Users\dasare\Desktop\Tor Browser\Browser\firefox.exe
  ```

---

### 4. 🌐 Outbound HTTPS Connection Made via Tor

- **Timestamp:** `2025-05-14T22:45:27.7040346Z`
- **Event:** Encrypted outbound connection initiated from `tor.exe` by user **dasare**.
- **Action Type:** **ConnectionSuccess**
- **Remote Endpoint:**
  - **IP:** `194.147.140.107`
  - **Port:** `443`
- **Initiating File:**
  ```text
  C:\Users\dasare\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe
  ```

---

### 5. 📡 Additional Network Activity on Known Tor Ports

- **Timestamps:** Post-launch, clustered around `22:45:30Z – 22:46:00Z`
- **Event:** Connection attempts on various Tor-related ports.
- **Action Type:** **ConnectionSuccess**, **ConnectionFailed**
- **Ports Observed:**
  - **Successful:** `443`, `9150`
  - **Failed:** `9150`, `9001` (others may vary)
- **Details:** Additional Tor network connections were established and failed on several ports, indicating ongoing activity through the Tor browser.


---

## 📝 Summary

User “dasare” downloaded and executed a silent install of the Tor Browser on the device threat-hunt-lab. Following the installation, numerous Tor-related files were placed on the user’s Desktop, including a file named tor-shopping-list.txt. At 22:44:42Z, the Tor Browser was actively launched, as evidenced by the execution of both firefox.exe and tor.exe. Shortly after, at 22:45:27Z, the browser successfully established an outbound encrypted connection to a known remote IP over port 443, with additional activity observed on other known Tor network ports such as 9150. These actions confirm the successful installation, launch, and operational use of the Tor network for outbound encrypted communications.

---

## 🚨 Response Taken

TOR usage was confirmed on endpoint threat-hunt-lab by the user dasare. The device was isolated, and the user's direct manager was notified.


---
