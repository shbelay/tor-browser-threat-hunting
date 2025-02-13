<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/shbelay/tor-browser-threat-hunting/blob/main/tor-usage-scenario-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "shbelay" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-02-12T23:57:37.5758047Z`.

These events began at: 2025-02-12T23:57:37.5758047Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName startswith "WindowsVM-shbel"
| where InitiatingProcessAccountName == "shbelay"
| where FileName contains "tor"
| where TimeGenerated >= datetime(2025-02-12T23:57:37.5758047Z)
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/da83343f-83c6-4f9f-8f48-8bb09fd684dc">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.6.exe". Based on the logs returned, at `2025-02-12T23:57:55.4584234Z`, an employee on the "windowsvm-shbel" device ran the file `tor-browser-windows-x86_64-portable-14.0.6.exe`.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName startswith "windowsvm-shbel"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/12ada836-7c5b-4aae-8cea-fd5d2e67ab42">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "shbelay" actually opened the TOR browser. There was evidence that they did open it at `2025-02-12T23:59:05.3435839Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where AccountName == "shbelay"
| where ProcessCommandLine has_any("tor.exe","firefox.exe","tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a6e394a3-459f-4fe6-a24d-f51505b16c9c">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-02-13T00:01:58.0359244Z`, an employee on the "shbelay" device successfully established a connection to the remote IP address `190.211.254.182` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\shbelay\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName startswith "windowsvm-shbel"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/73b46cd2-ae8e-4457-85a0-4af94f8a61cc">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-02-12T23:57:37.5758047Z`
- **Event:** The user "shbelay" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\shbelay\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-02-12T23:57:55.4584234Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.6.exe`, initiating the installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.6.exe`
- **File Path:** `C:\Users\shbelay\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-02-12T23:59:05.3435839Z`
- **Event:** User "shbelay" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\shbelay\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-02-13T00:01:58.0359244Z`
- **Event:** A network connection to IP `190.211.254.182` on port `9001` by user "shbelay" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\shbelay\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-02-13T00:02:02.8075606Z` - Connected to `2.58.52.163` on port `9001`.
  - `2025-02-13T00:02:09.3109154Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "shbelay" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-02-13T00:02:21.639482Z`
- **Event:** The user "shbelay" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\shbelay\Desktop\tor-shopping-list.txt`

![image](https://github.com/user-attachments/assets/5c968a3e-51fd-4fc7-87a4-d6af7fe567a6)

---

## Summary

The user "shbelay" on the "WindowsVM-shbel" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `windowsvm-shbel` by the user `shbel`. The device was isolated, and the user's direct manager was notified.

---
