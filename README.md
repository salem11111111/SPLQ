**.lock files**, any dest
Searches Sysmon logs from the last 24 hours for .lock files, extracts the Windows username from the file path, and displays details about when and where those files were seen, along with the process and host information.
  ```
  index=sysmon file_name="*.lock" earliest=-24h latest=now | rex field=file_path "C:\\\\Users\\\\(?<user>[^\\\\]+)\\\\"
  | table _time file_name file_path host process_exec app Computer user
  ```

**Specific dest+files**

  ```
  index=*  (file_name="file1.lock"  OR file_name="file2.lock" OR file_name="file3.lock" OR file_name="file4.lock" OR file_name="file5.lock" OR file_name="file6.lock" OR file_name="file7.lock" OR file_name="write.lock"  ) (dest="<>" OR dest="<>" OR dest="<>") | table file_name file_path host process_exec app Computer
  ```

**Count of failed auth attempts from each user**
```
  index=firewall (auth_method=LDAP OR auth_method=RADIUS)
  | stats count values(action) as actions values(src) as src_ips by user
```

**Index ip/user**
  ```
  index=firewall user=""
  | stats count by action auth_method src
  ```

**Check if exact chain repeats for host**
  ```
  index=* earliest=-30d latest=now
  host=""
  "ping.exe" AND "cmd.exe" 
  | table _time user process_name process_path parent_process_name parent_process_path parent_command_line
  | sort _time
  ```

**See all similar events across all hosts**

  ```
  index=* earliest=-30d latest=now
  process_path="C:\\Windows\\System32\\PING.EXE"
  process_parent_path="C:\\Windows\\System32\\cmd.exe"
  process_parent_command_line="*GoogleUpdater*uninstall.cmd*"
  | table _time host user process_name process_path process_parent_name process_parent_path process_parent_command_line
  | sort _time
  ```

**Check malicious IP traffic through firewall**
  ```
  index=firewall src=""
  ```

**Inactive Index Detected - Rule**
```
index=""
```

**Confirm indexes you're allowed to search**
  ```
  | eventcount summarize=false index=*
  ```

**Search for specific .exe unknown index/source/sourcetype**
  ```
  (index=sysmon OR index=wineventlog OR index=os)
  ".exe"
  | table _time, host, source, sourcetype, _raw
  | sort -_time
   ```

**Status of host:**
  ```
  index=your_index
  | stats values(orig_host) as Hostnames
  ```

  ```
  index=* (host="" OR host="" OR host="" OR host="")
  | table _time host orig_host src_ip dest_ip ComputerName
  ```

  ```
  | metadata type=hosts index=* | dedup host  | eval current_time=now()  | eval timediff=round((current_time-lastTime)/60,2) | eval threshold=120 | eval Current_status=if(timediff>threshold,"missed","active")  | convert ctime(lastTime), ctime(current_time), ctime(firstTime)  | fields - type,recentTime,totalCount  | fields host,firstTime,lastTime,current_time,,Current_status,timediff,threshold  | sort - Current_status,timediff  | rename timediff as timediff(m)  | search host="" OR host="" OR host="" OR host="" 
  ```

**Excessive Logins**
  ```
  index=* src="" (signature_id=4776 OR action=success)
  | eval account_type=if(match(user, "\\$$"), "Machine Account", "Human Account")
  | stats 
      count AS total_events
      values(action) AS actions
      dc(action) AS action_types
      values(dest) AS dests
      dc(dest) AS unique_dests
      values(account_type) AS account_types
      values(user) AS users
      min(_time) AS first_seen
      max(_time) AS last_seen
  BY src
  | convert ctime(first_seen) ctime(last_seen)
  | sort -total_events
  ```

**Excessive Logins: Human/Machine**
```
  index=* signature_id=4776 src=""
  | eval account_type=if(match(user,"\\$$"),"Machine","Human")
  | stats 
      count AS total_events 
      sum(eval(action="success")) AS success_count 
      sum(eval(action="failure")) AS failure_count 
      values(dest) AS destinations
    BY user, account_type
  | eval success_count=coalesce(success_count,0)
  | eval failure_count=coalesce(failure_count,0)
  | sort account_type
  ```

**RDP connection correlation**
  ```
  index=*
  (EventCode=4624 OR EventCode=4625 OR EventCode=4648 OR EventCode=4672)
  | eval LogonType=case(
      LogonType=10,"RDP",
      LogonType=2,"Interactive",
      true(), LogonType
    )
  | search LogonType="RDP"
  | search Account_Name IN ("user1","user2","user3","user4","user5")
  | stats 
      count AS TotalAttempts,
      dc(DestinationHost) AS UniqueDestHosts,
      values(SourceHost) AS SourceHosts,
      earliest(_time) AS FirstSeen,
      latest(_time) AS LastSeen
    BY Account_Name, SourceHost, DestinationHost
  | eval Suspicious=if(
      TotalAttempts>5 OR (_time<strptime("08:00","%H:%M") OR _time>strptime("18:00","%H:%M")),
      "Yes", "No"
  )
  | table Account_Name, SourceHost, DestinationHost, TotalAttempts, UniqueDestHosts, FirstSeen, LastSeen, Suspicious
  ```
