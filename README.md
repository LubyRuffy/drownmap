# drownmap

Security tool, scan your environments for the SSLv2 DROWN vulnerability.

DrownMap is designed for testing large volumes of internal (or external) network services that employ SSL/TLS for encryption. The aim is a tool that can test entire networks in an automated fashion, producing a report of all vulnerable hosts and their services. A list of potentially compromised certificates is also returned. Coupled with nmap this can be done even without a prior list of which servers and active network devices you need to test. For webservers and the like serving multiple domains, remember to consider all of their virtualhosts also.

Requirements: nmap, ruby, openssl (s_client)

```
DrownMap / Ymon Oy / www.ymon.fi, info@ymon.fi

This tool can generate large amounts of SSL connections.
Software provided as is, all use is at users own responsibility.

Note, nmap logs should be in Greppable Format (-oG)
Requirements: nmap, ruby, openssl (s_client)

Example:
  sudo nmap -Pn -sT -p 443,465,587,636,993,995,8443 --open -oG ssl-net50.log 192.168.50.0/24
  ruby ./drownmap.rb ssl-net*.log | tee results-net50.txt

Examples results will be displayed, and written to results-net50.txt file.", ""

Usage: drownmap [options] [FILE(S)]...
    -d, --delay=SECONDS              Delay between SSL connections (Decimal, default=0.01)
    -h, --help                       Prints this help
    -v, --version                    Prints version
```

Output format example:
```
{"vuln"=>false, "conn"=>"192.168.1.132:443", "name"=>"site1.example.com", "cert"=>[]}
{"vuln"=>true, "conn"=>"192.168.1.133:443", "name"=>"site2.example.com", "cert"=>["subject=/C=FI/ST=Uusimaa/L=Helsinki/O=Example Inc./OU=Web Services/CN=Example/emailAddress=support@example.com\n", "issuer=/C=FI/ST=Uusimaa/L=Helsinki/O=Example Inc./OU=CA Services/CN=Example/emailAddress=support@example.com\n"]}

Where:

vuln=> If server responded to SSLv2 and is vulnerable
conn=> IP:port connected to
name=> DNS name if available
cert=> Cert in use on server if vulnerable.
```
