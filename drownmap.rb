#!/usr/bin/env ruby

#   Copyright 2016 Ymon Oy
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

ver = 1.0

# Reads NMAP regexp format, uses openssl s_client to check for SSLv2 support.

require 'timeout'
require 'open3'
require 'optparse'

$stderr.puts "DrownMap v#{ver} / Ymon Oy / www.ymon.fi, info@ymon.fi", "",
"This tool can generate large amounts of SSL connections.",
"Software provided as is, all use is at users own responsibility.", ""

def help
return <<END
Note, nmap logs should be in Greppable Format (-oG)
Requirements: nmap, ruby, openssl (s_client)

Example:
  sudo nmap -Pn -sT -p 443,465,587,636,993,995,8443 --open -oG ssl-net50.txt 192.168.50.0/24
  ruby #{$0} ssl-net*.log | tee results-net50.txt

Examples results will be displayed, and written to results-net50.txt file.", ""

END
exit(1)
end

options = {:delay=>0.01}
OptionParser.new do |opts|
  opts.on('-d', '--delay=SECONDS', Float, 'Delay between SSL connections (Decimal, default=0.01)') { |s| options[:delay] = s }
  opts.on('-h', '--help', 'Prints this help') { $stderr.puts help(), opts }
  opts.on('-v', '--version', 'Prints version') { $stderr.puts "DrownMap version 1.0."; exit(1) }
  opts.on('FILE(S)') {}

  if ARGV.empty?
    $stderr.puts help
    $stderr.puts opts
  end
end.parse!

ARGV.each do |f|
  handle = File.open(f)
  puts handle.each_line.select { |line| /^Host:.*(?=Ports:)Ports:/.match(line) }
  .inject([]) { |acc,line| 
    ip, name = /^Host: (.*?) \((.*?)\)/.match(line)[1..2]
    line.scan(/(\d+)\/open/)[0].each { |port|
      acc += [{'ip' => ip, 'name' => name, 'port' => port}]
    }
    acc
  }
  .map { |conn|
    $stderr.puts "# Processing #{conn['ip']}:#{conn['port']} (#{conn['name']})"
    ssl2 = "error" # Vulnerable? Default to error
    cert = ""
    begin
      Timeout::timeout(5) {
        stdin, stdout, stderr, wait_thr = Open3.popen3('openssl', 's_client', '-ssl2', '-connect', "#{conn['ip']}:#{conn['port']}");
        stdin.close
        cert = stdout.each_line.select { |line| /^(subject=|issuer=)/.match(line) }
        stdout.close; stderr.close
        ssl2 = wait_thr.value.exitstatus == 0 ? true : false;
      }
    rescue Timeout::Error
      ssl2 = "timeout"
    end
    sleep(options[:delay])
    {'vuln' => ssl2, 'conn' => "#{conn['ip']}:#{conn['port']}", 'name' => conn['name'], 'cert' => cert}
  }
  .sort_by { |h| h['vuln'] == false ? 0 : 1 }
end
