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
This Splunk query searches across all indexes (index=*) for events from the last 30 days (earliest=-30d latest=now). It specifically looks for events where the process path matches "C:\\Windows\\System32\\PING.EXE" (meaning the ping.exe program was run), the parent process path matches "C:\\Windows\\System32\\cmd.exe" (meaning the command was run from the Windows Command Prompt), and the parent process command line contains the phrase "GoogleUpdater*uninstall.cmd" (meaning it was triggered by a script related to Google Updater uninstall). The pipe (|) sends these results into a table command, which neatly organizes the data into columns: _time (when the event happened), host (the machine where it happened), user (the account that ran the process), process_name, process_path, process_parent_name, process_parent_path, and process_parent_command_line (the full command line of the parent process). Finally, | sort _time orders the results by time so they are shown from oldest to newest. This query is designed to identify and track specific instances where ping.exe is launched via a command prompt script related to GoogleUpdater uninstall processes — a potential security or troubleshooting use case.

  ```
  index=* earliest=-30d latest=now
  process_path="C:\\Windows\\System32\\PING.EXE"
  process_parent_path="C:\\Windows\\System32\\cmd.exe"
  process_parent_command_line="*GoogleUpdater*uninstall.cmd*"
  | table _time host user process_name process_path process_parent_name process_parent_path process_parent_command_line
  | sort _time
  ```

**Check malicious IP traffic through firewall**
This Splunk query searches in the firewall index (index=firewall) for log events where the src field is empty (src=""). The src field normally contains the source IP address of network traffic, so filtering for empty values means this query is looking for firewall logs where the source IP address is missing. This could point to unusual or incomplete logs, possible misconfigurations, or specific network events where the source was not recorded. Because there is no additional filtering or formatting here, the query will return all matching events in raw form so you can inspect them directly.
  ```
  index=firewall src=""
  ```

**Inactive Index Detected - Rule**
This Splunk query searches for log events in a specific index, but here the index name is empty (index=""). In Splunk, an index is like a folder or database that stores specific types of log data, and you normally specify its name so Splunk knows where to search. Leaving it empty means the query is incomplete — Splunk won’t know which index to search unless a default index is set in your system. Without a valid index name or additional filters, this query won’t return meaningful results. Essentially, this is like telling someone “look in a folder” without saying which folder.
```
index=""
```

**Confirm indexes you're allowed to search**
This Splunk query uses eventcount to quickly count how many events exist in your Splunk data. The index=* part tells Splunk to search across all indexes, meaning it will look at every dataset you have access to. The option summarize=false means Splunk will skip using any precomputed summaries and instead count events directly from the raw data, which is slower but more accurate and up-to-date. This command is useful when you want a quick overview of the number of events in your environment without applying any filters. It essentially gives you a raw total of events for each index, helping you understand the size and activity of your log data.

  ```
  | eventcount summarize=false index=*
  ```

**Search for specific .exe unknown index/source/sourcetype**
This Splunk query searches across three indexes — sysmon, wineventlog, and os (index=sysmon OR index=wineventlog OR index=os) — looking for any events that contain the text .exe, which usually indicates executable files being run on a system. The .exe filter is not field-specific, so Splunk searches for it anywhere in the raw event data. The pipe (|) sends the results to the table command, which organizes the output neatly into columns: _time (when the event happened), host (the machine that generated the event), source (the file or data source), sourcetype (type of data, such as logs from Sysmon or Windows events), and _raw (the full raw log entry). Finally, | sort -_time sorts the results in descending order by time, so the newest events appear first. This query is useful for tracking executable activity across multiple data sources in your environment.
  ```
  (index=sysmon OR index=wineventlog OR index=os)
  ".exe"
  | table _time, host, source, sourcetype, _raw
  | sort -_time
   ```

**Status of host:**
This Splunk query searches in a specific index called your_index (index=your_index) — which should be replaced with the actual index name where your data lives. The pipe (|) sends the results to the stats command, which summarizes data. Here, values(orig_host) as Hostnames tells Splunk to collect all unique values of the orig_host field (which usually represents the original hostname where the event came from) and display them under a new column called Hostnames. Essentially, this query gives you a simple list of all unique hostnames found in that index, making it useful for understanding which machines are generating events.
  ```
  index=your_index
  | stats values(orig_host) as Hostnames
  ```

  ```
  index=* (host="" OR host="" OR host="" OR host="")
  | table _time host orig_host src_ip dest_ip ComputerName
  ```
This Splunk query uses the metadata command to gather summary information about all hosts in Splunk (type=hosts index=*). It starts by finding all host entries and then uses dedup host to keep only one entry per host. The eval current_time=now() command creates a field storing the current time, and eval timediff=round((current_time-lastTime)/60,2) calculates the time difference (in minutes) between now and the last time data was seen from each host. It then sets a threshold of 120 minutes and uses eval Current_status=if(timediff>threshold,"missed","active") to label each host as "active" or "missed" depending on whether it’s been longer than 120 minutes since the last log. The convert ctime(...) commands turn time fields into human-readable formats. It removes unnecessary fields with fields - type,recentTime,totalCount and then keeps only relevant columns with fields host,firstTime,lastTime,current_time,Current_status,timediff,threshold. It sorts the results so "missed" hosts appear first, renames timediff to timediff(m) for clarity, and finally uses search host="" OR host="" ... to filter for specific hosts (placeholders here). This query is designed to monitor host activity and flag hosts that haven’t reported data recently.
  ```
  | metadata type=hosts index=* | dedup host  | eval current_time=now()  | eval timediff=round((current_time-lastTime)/60,2) | eval threshold=120 | eval Current_status=if(timediff>threshold,"missed","active")  | convert ctime(lastTime), ctime(current_time), ctime(firstTime)  | fields - type,recentTime,totalCount  | fields host,firstTime,lastTime,current_time,,Current_status,timediff,threshold  | sort - Current_status,timediff  | rename timediff as timediff(m)  | search host="" OR host="" OR host="" OR host="" 
  ```

**Excessive Logins**
This Splunk query searches across all indexes (index=*) for events where the src field is empty (src="") and either signature_id=4776 (which relates to Windows authentication events) or action=success (indicating successful authentication attempts). It uses eval account_type=if(match(user, "\\$$"), "Machine Account", "Human Account") to classify accounts: if the username ends with a $, it’s considered a “Machine Account” (like a computer account), otherwise it’s a “Human Account.” The stats command groups results by src and calculates various summaries: the total number of events (count AS total_events), all action types seen (values(action)), the number of different actions (dc(action)), all destination systems (values(dest)), the count of unique destinations (dc(dest)), all account types (values(account_type)), all usernames involved (values(user)), the first time an event was seen (min(_time)), and the last time (max(_time)). The convert ctime(first_seen) ctime(last_seen) command turns those timestamps into human-readable dates, and sort -total_events lists results with the most active sources at the top. This query is useful for summarizing authentication activity from sources with missing IP information and detecting unusual patterns of logins across accounts.
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
 This Splunk query searches across all indexes (index=*) for events where signature_id=4776 — a common ID for Windows authentication events — and where the source IP (src) is empty (src=""). This helps find authentication attempts that may be missing source information. The query then uses eval account_type=if(match(user,"\\$$"),"Machine","Human") to classify the account type: if the username ends with a $, it’s treated as a “Machine” account (like computer accounts), otherwise it’s treated as a “Human” account. Next, the stats command groups the results by user and account_type and calculates: the total number of events (count AS total_events), the number of successful logins (sum(eval(action="success")) AS success_count), the number of failed logins (sum(eval(action="failure")) AS failure_count), and all destination systems involved (values(dest) AS destinations). The eval success_count=coalesce(success_count,0) and eval failure_count=coalesce(failure_count,0) ensure missing values are replaced with 0 so the counts are always numbers. Finally, sort account_type organizes the results so that machine accounts and human accounts are grouped. This query is useful for tracking authentication activity and spotting unusual patterns in failed or successful logins.
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
This Splunk query searches across all indexes (index=*) for Windows security events with EventCode values 4624, 4625, 4648, or 4672, which are all related to user logons and authentication attempts. The eval LogonType=case(...) part converts numeric logon type codes into meaningful labels (e.g., 10 becomes "RDP" for Remote Desktop logons, 2 becomes "Interactive" for direct logons). Then, | search LogonType="RDP" filters to only include Remote Desktop logons. Next, | search Account_Name IN ("user1","user2",...) restricts results to specific usernames. The stats command summarizes the data grouped by Account_Name, SourceHost, and DestinationHost, calculating: total login attempts (count AS TotalAttempts), the number of unique destination hosts (dc(DestinationHost)), all source hosts seen (values(SourceHost)), and the first and last times those logons happened. The eval Suspicious=if(...) adds a flag to mark entries as "Yes" if there are more than 5 attempts or if the logons happen outside of normal hours (before 8:00 AM or after 6:00 PM), otherwise "No". Finally, the table command neatly displays results with relevant columns, showing which accounts, sources, and destinations may have suspicious Remote Desktop activity.
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
