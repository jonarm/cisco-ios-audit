# cisco-ios-audit #
Python script that parses a Cisco IOS configuration file and generates a report to efficiently perform an IT Security Audit

## Requirements ##
* Python versions 2.6, 2.7 or 3.2+
* ciscoconfparse module
* python setuptools


## Usage ##
```
./cisco-ios-audit.py ConfigFile
```

## Example ##
1. Run the script
  ```
  ./cisco-ios-audit.py ConfigFile
  ```

Notes:
* Ensure that the configuration files don't have 2 consecutive blank lines as it introduces inaccurate results.
    * This sed command could be used to remove blank lines in the config file. `sed -i '/^\s*$/d' ConfigFile`
* Rename configuration files with bad format.
     * Sample - `2015.05.25 07.23 switch.txt`. This should be renamed to `switch.txt`.
* Use "for loop" for multiple configuration files
