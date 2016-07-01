# pingr

## Overview
pingr is a utility to identify hosts on your internal or external network. It has the ability to ping hosts in a given range (CIDR notation) and report those which reply. Additionally, for hosts that are up, a quick check is made to see if port 80 is open. This tool was made in an effort to circumvent issues with nmap reporting incorrect results (all hosts in a block reporting as "up") due to local VMWare adapters, and to make it easier to find CTF boxes on the local net. It's very simple and prone to false negatives (if hosts are configured to not respond to ICMP packets), but was made for a very circumstantial use-case. Regardless, it's multi-threaded and pretty quick, and so far reliable. The same results could be obtained with any number of tools or methods, but building stuff in ruby is fun. :)

## Requirements
Currently only compatible with Unix-based systems.

```
gem install colorize typhoeus net-ping ipaddress
```

## Usage
```
Example Usage: ruby pingr.rb < -f /path/to/file | -r 192.168.1.0/24 | -i 192.168.1.205 | -a | -h >
    -f, --file=FILE                  Specify the path to the file to parse. IPs will be parsed from say, log output.
    -r, --range=RANGE                Specify a range to scan in CIDR format. (ex. 192.168.1.0/24)
    -i, --ip=IP                      Specify a single IP to scan
    -a, --auto                       Auto-scan based on current IP address. Warning: Mac/Linux Support Only
    -h, --help                       Display this screen
```

![Screenshot](http://cl.ly/3X1h240M3C0c/Screen%20Shot%202016-06-30%20at%206.15.35%20PM.png)

## TODO
- Include more options to gather info about hosts (netbios, more port scanning, etc.)
- Add option to choose number of threads to use

## License
See LICENSE