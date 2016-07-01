#!/usr/bin/env ruby

## Pingr -- identify hosts on your network

require 'optparse'
require 'colorize'
require 'typhoeus'
require 'net/ping'
require 'ipaddress'
require 'thread'
require 'socket'

trap("SIGINT") { exit! } # catch ctrl+c during ping scan to halt

@options = {}
optparse = OptionParser.new do |opts|

    opts.banner = "Example Usage: ruby pingr.rb < -f /path/to/file | -r 192.168.1.0/24 | -i 192.168.1.206 | -a | -h >"
    @options[:banner] = opts

    @options[:file] = nil
    opts.on('-f', '--file=FILE', String, 'Specify the path to the file to parse. IPs will be parsed from say, log output.') do |file|
        @options[:file] = file
    end

    @options[:range] = nil
    opts.on( '-r', '--range=RANGE', String, 'Specify a range to scan in CIDR format. (ex. 192.168.1.0/24)') do |range|
        @options[:range] = range
    end

    @options[:ip] = nil
    opts.on( '-i', '--ip=IP', String, 'Specify a single IP to scan') do |ip|
        @options[:ip] = ip
    end

    # @options[:broadcast] = nil
    # opts.on( '-b', '--broadcast=ADDR', String, 'Specify the broadcast address to ping (in order to populate local arp tables). (ex. 192.168.1.255)') do |broadcast|
    #   @options[:broadcast] = broadcast
    # end

    @options[:auto] = nil
    opts.on( '-a', '--auto', 'Auto-scan based on current IP address. Warning: Mac/Linux Support Only') do |auto|
        @options[:auto] = true
    end

    opts.on_tail('-h', '--help', "Display this screen\n\n") do
        puts opts
        exit
    end

end

if !ARGV[0]
    puts @options[:banner]
    exit
end

optparse.parse!

@hosts_up = []
@ip_data = []
@workers = []

def ping_host(ip)
    host_data = {:ip => nil, :reverse_dns => nil, :port_80 => nil, :body => nil}
    response = Net::Ping::External.new(ip,nil,2)

    if response.ping? == true
        reverse_dns = `host #{ip}`.match(/pointer (.*)\./)
        
        # TODO
        host_netbios = nil#`nbtscan #{ip}`
        
        http_response = Net::Ping::HTTP.new(ip,nil,5,)
        
        if http_response.ping? == true
            port_80 = "Port 80 open"
            
            res = Typhoeus.get(ip)
            if res.body.size > 0
                # body = res.body.lines.first(5)
                body = res.body.match(/<title>(.*)<\/title>/)
            end
        end

        host_data[:ip] = ip
        host_data[:reverse_dns] = reverse_dns[1] if reverse_dns != nil
        host_data[:host_netbios] = host_netbios if host_netbios != nil
        host_data[:port_80] = port_80 if port_80 != nil
        host_data[:body] = body[1] if body != nil
        
        @hosts_up.push(host_data)
    end
end

def create_worker(slice)
    @workers << Thread.new { 
        slice.each do |ip|

            ip = ip.to_s
            ping_host(ip) 
            
        end
    }
end

def slice_range(range)
    ips = IPAddress "#{range}"
    
    if ips.count >= 65536
        puts "Using #{ips.count/128} threads".light_red
        puts "This could take a while...".light_red
        slice = ips.count/128
    elsif ips.count >= 128
        puts "Using #{ips.count/64} threads".light_red
        slice = ips.count/64
    elsif ips.count >= 24
        puts "Using #{ips.count/12} threads".light_red
        slice = ips.count/12
    elsif ips.count >= 2
        puts "Using #{ips.count/2} threads".light_red
        slice = ips.count/2
    else
        puts "Using #{ips.count/1} threads".light_red
        slice = ips.count/1
    end

    ips.each_slice(slice) do |s|
        @ip_data.push(s)
    end

    # create a thread for each slice in ip_data
    @ip_data.each { |slice| create_worker(slice) }

    # close each thread after it's finished
    @workers.each { |thread| thread.join }
end

def get_local_ips
    #get assigned ips for each network interface (all will be scanned)
    Socket.ip_address_list.select{|intf| intf.ipv4? and !intf.ipv4_loopback? and !intf.ipv4_multicast?}
end

def report_findings
    puts "Hosts up: #{@hosts_up.count}".black.on_green
    @hosts_up = @hosts_up.sort_by { |hsh| hsh[:ip].split('.').map{ |octet| octet.to_i} }

    @hosts_up.each do |h|
        puts "#{h[:ip]}".light_green + " \t#{h[:reverse_dns]}".light_cyan + " \t#{h[:port_80]}" + " \t#{h[:body]}"
    end
    
    # empty all arrays
    @hosts_up = []
    @ip_data = []
    @workers = []
end

if @options[:file]
    path = @options[:file]
    @targets = []
    File.open(path, "r") do |f|
        f.lines.each do |l|

            ip = l.scan(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)
            
            if ip.count > 0
                ip.each do |i|
                    puts "IP is #{i}"
                    @targets.push i
                end
            else
                # file is empty
                puts "No IPs were found in your file...".light_red
                exit
            end
        end
    end

    @targets.each do |ip|
        ping_host(ip)
    end
    report_findings
end

if @options[:range]
    slice_range(@options[:range])
    report_findings
end

if @options[:ip]
    ping_host(@options[:ip])
    report_findings
end

if @options[:auto]
    ips = []
    get_local_ips.each do |ip|
        range = ip.ip_address.gsub(/(\d\d?\d?$)/, "1/24") # replace last octet w/ (hardcoded for now) range
        puts "Scanning #{range}...".light_yellow.on_black
        slice_range(range)
        report_findings
    end
end