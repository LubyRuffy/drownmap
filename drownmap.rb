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

ver = "1.0.2"

# Reads NMAP regexp format, uses openssl s_client to check for SSLv2 support.
# Supports StartTLS for smtp, pop3, imap, ftp, xmpp if OpenSSL version recent.

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
  sudo nmap -Pn -sT -p 21,25,110,143,443,465,587,636,993,995,5222,8443 --open -oG ssl-net50.log 192.168.50.0/24
  ruby #{$0} ssl-net*.log | tee results-net50.txt

Examples results will be displayed, and written to results-net50.txt file

END
exit(1)
end

options = {:delay=>0.01, :timeout=>5.0}
OptionParser.new do |opts|
  opts.on('-d', '--delay=SECONDS', Float, 'Delay between SSL connections (Decimal, default=0.01)') { |s| options[:delay] = s }
  opts.on('-t', '--timeout=SECONDS', Float, 'Time to wait for SSL handshake (Decimal, default=5.0)') { |s| options[:timeout] = s }
  opts.on('-h', '--help', 'Prints this help') { $stderr.puts help(), opts }
  opts.on('-v', '--version', 'Prints version') { $stderr.puts "DrownMap version #{ver}."; exit(1) }
  opts.on('FILE(S)') {}

  if ARGV.empty?
    $stderr.puts help
    $stderr.puts opts
  end
end.parse!

class DrownMap
  def initialize(options)
    @starttls_ports = {21=>'ftp', 25=>'smtp', 110=>'pop3', 143=>'imap', 5222=>'xmpp'}
    @starttls_excludes = '-no_tls1_2 -no_tls1_1 -no_tls1 -no_ssl3'
    @options = options
  end

  def process(handle)
    return handle.each_line.select { |line| /^Host:.*(?=Ports:)Ports:/.match(line) }
    .inject([]) { |acc,line| 
      ip, name = /^Host: (.*?) \((.*?)\)/.match(line)[1..2]
      line.scan(/(\d+)\/open/).each { |port|
        acc += [{'ip' => ip, 'name' => name, 'port' => port[0]}]
      }
      acc
    }
    .map { |conn|
      $stderr.puts "# Processing #{conn['ip']}:#{conn['port']} (#{conn['name']})"
      ssl2 = "error" # Vulnerable? Default to error
      cert = ""
      begin
        starttls_proto = @starttls_ports.fetch(conn['port'].to_i, nil) 
        args = starttls_proto != nil ? "-starttls #{starttls_proto} #{@starttls_excludes}" : '-ssl2' 
        Timeout::timeout(@options[:timeout]) {
          stdin, stdout, stderr, wait_thr = Open3.popen3("openssl s_client -connect #{conn['ip']}:#{conn['port']} " + args);
          stdin.close
          cert = stdout.each_line.select { |line| /^(subject=|issuer=)/.match(line) }
          stdout.close; stderr.close
          ssl2 = wait_thr.value.exitstatus == 0 ? true : false
        }
      rescue Timeout::Error
        ssl2 = "timeout"
      end
      ssl2 = 'error' if ssl2 == true && cert.empty?
      sleep(@options[:delay])
      {'vuln' => ssl2, 'conn' => "#{conn['ip']}:#{conn['port']}", 'name' => conn['name'], 'cert' => cert}
    }
  end
end

mapper = DrownMap.new(options)

puts ARGV.inject([]) { |acc, f| 
  handle = File.open(f)
  acc += mapper.process(handle)
  handle.close
  acc
}
.sort_by { |h| h['vuln'] == false ? 0 : 1 }
