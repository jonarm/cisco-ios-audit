# cisco-ios-audit #
Python script that parses a Cisco IOS configuration file and generates a report to efficiently perform an IT Security Audit

## Requirements ##
* Python versions 2.6, 2.7 or 3.2+
* ciscoconfparse module
* python setuptools


## Usage ##
```
./myriad-ssh.py
```

## Example ##
1. Run the script
  ```
  ./myriad-ssh.py
  ```

2. Enter the necessary details
  ```
  Enter username: uname
  Password: pass
  Enter the remote command: date && uname -a
  Enter the serverlist file:/home/uname/serverlistfile
  ```
  > Note: Server list file contains the server hostnames/IPs written in one column

3. Progress and Output
  ```
  Total number of servers: 5
  Progress: 80%............Done
  ```
  Output file: **myriad-ssh-log.csv**
