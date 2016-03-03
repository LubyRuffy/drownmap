# drownmap
Security tool, scan your environments for the SSLv2 DROWN vulnerability.

```
DrownMap / Ymon Oy / www.ymon.fi, info@ymon.fi

This tool can generate large amounts of SSL connections.
Software provided as is, all use is at users own responsibility.

Note, nmap logs should be in Greppable Format (-oG)
Requirements: nmap, ruby, openssl (s_client)

Example:
  sudo nmap -Pn -sT -p 443,465,587,636,993,995,8443 --open -oG ssl-net50.txt 192.168.50.0/24
  ruby ./drownmap.rb ssl-net*.log | tee results-net50.txt
{quote}

Examples results will be displayed, and written to results-net50.txt file.", ""

Usage: drownmap [options] [FILE(S)]...
    -d, --delay=SECONDS              Delay between SSL connections (Decimal, default=0.01)
    -h, --help                       Prints this help
    -v, --version                    Prints version
```
