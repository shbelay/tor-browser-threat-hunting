# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - Current Dread Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion```
   - Dark Markets Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumyeudtha62s4oaowwm7ifmnunz3khs4sllhvinphfm4nirfcqd.onion```
6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// Focused on a specific user and device
DeviceFileEvents
| where DeviceName startswith "WindowsVM-shbel"
| where InitiatingProcessAccountName == "shbelay"
| where FileName contains "tor"
| order by TimeGenerated desc

// TOR Browser being installed
DeviceProcessEvents
| where DeviceName startswith "windowsvm-shbel"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where DeviceName startswith "WindowsVM-shbel"
| where InitiatingProcessAccountName == "shbelay"
| where FileName contains "tor"
| where TimeGenerated >= datetime(2025-02-12T23:57:37.5758047Z)
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

// TOR Browser or service was launched
DeviceProcessEvents
| where DeviceName startswith "windowsvm-shbel"
| where ProcessCommandLine has_any("tor.exe","firefox.exe","tor-browser.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName startswith "windowsvm-shbel"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Surapheal Belay
- **Author Contact**: https://www.linkedin.com/in/shbelay/
- **Date**: February 13, 2025
