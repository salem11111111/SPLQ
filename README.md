**.lock files**, 
This is a Splunk search query that looks for specific log events in your system data. It starts with index=sysmon, which tells Splunk to search in the sysmon index (a place where Sysmon logs are stored). The next part, file_name="*.lock", filters results to only show files whose names end in .lock. The earliest=-24h latest=now part limits the search to the last 24 hours. Then | rex field=file_path "C:\\\\Users\\\\(?<user>[^\\\\]+)\\\\" is using a regular expression to extract a piece of information — here, it looks inside the file path and pulls out the username from the Windows file path, storing it in a field called user. Finally, | table _time file_name file_path host process_exec app Computer user tells Splunk to show the results in a neat table containing those specific columns: the time of the event, file name, file path, host, process executed, app, computer name, and the extracted user. Essentially, it’s a way to search for .lock files in Sysmon logs from the past day and display useful details in an organized format.
  ```
  index=sysmon file_name="*.lock" earliest=-24h latest=now | rex field=file_path "C:\\\\Users\\\\(?<user>[^\\\\]+)\\\\"
  | table _time file_name file_path host process_exec app Computer user
  ```

**Specific dest+files**
This Splunk query searches across all indexes (index=*) to look for specific events. It filters results so only events where the file name matches any of the listed .lock files — like file1.lock, file2.lock, up to file7.lock and write.lock — are included. That’s what the (file_name="..." OR file_name="..." …) part does: it’s a list of conditions joined with “OR” so Splunk returns matches for any of them. The (dest="<>" OR dest="<>" OR dest="<>") part further filters the results to only include events where the destination (dest) matches one of those specific values (here represented as placeholders <>). The pipe symbol (|) sends the filtered results into the next step, which is table file_name file_path host process_exec app Computer, telling Splunk to display the results in a clean table containing those columns: file name, file path, host, process executed, app, and computer name. Essentially, this query is designed to track certain .lock files hitting specific destinations and present that information in an easy-to-read table.
  ```
  index=*  (file_name="file1.lock"  OR file_name="file2.lock" OR file_name="file3.lock" OR file_name="file4.lock" OR file_name="file5.lock" OR file_name="file6.lock" OR file_name="file7.lock" OR file_name="write.lock"  ) (dest="<>" OR dest="<>" OR dest="<>") | table file_name file_path host process_exec app Computer
  ```

**Count of failed auth attempts from each user**
This Splunk query searches in the firewall index (index=firewall) to find log events related to authentication attempts. It filters for events where the authentication method (auth_method) is either LDAP or RADIUS — these are common protocols for validating user access. The pipe (|) sends the filtered events to the next step, which is a stats command. The stats command summarizes data: count gives the total number of matching events, values(action) as actions collects all unique actions taken and labels them as actions, and values(src) as src_ips collects all unique source IP addresses and labels them as src_ips. The by user part groups the results by each username so you can see, for each user, how many authentication events occurred, what actions were taken, and what source IPs were involved. In short, this query gives a concise summary of LDAP or RADIUS authentication activity grouped by user.
```
  index=firewall (auth_method=LDAP OR auth_method=RADIUS)
  | stats count values(action) as actions values(src) as src_ips by user
```

**Index ip/user**
This Splunk query searches in the firewall index (index=firewall) and filters for events where the user field is empty (user=""). This means it’s looking for firewall logs where no username is recorded. The pipe (|) sends those results to the stats command, which summarizes the data. Specifically, count gives the total number of matching events, and by action auth_method src means the results will be grouped by the combination of action (what the firewall did, e.g., allow or deny), auth_method (the authentication method used), and src (the source IP address). The output is essentially a table that shows, for each combination of action, authentication method, and source IP, how many times it occurred — helping you spot patterns like repeated failed attempts or unusual activity with no associated username.
  ```
  index=firewall user=""
  | stats count by action auth_method src
  ```

**Check if exact chain repeats for host**
This Splunk query searches across all indexes (index=*) for log events from the last 30 days (earliest=-30d latest=now). It filters those events so they only include logs where the host field is empty (host=""), meaning there’s no host name recorded for the event. It further filters to only include events that contain both "ping.exe" and "cmd.exe" — looking for cases where both of these processes appear in the logs together, which can sometimes indicate unusual activity or scripted commands. The pipe (|) sends the results to the next step, table, which formats the output neatly into columns: _time (when the event occurred), user (the account running the process), process_name, process_path, parent_process_name, parent_process_path, and parent_command_line (details about the parent process and commands executed). Finally, | sort _time arranges the results in chronological order so you can review the events over time. This query is essentially designed to track potential suspicious command activity involving ping.exe and cmd.exe in the last month.
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
