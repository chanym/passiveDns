#!/usr/bin/ruby

if ARGV.length != 1
	puts "Usage - ./passiveDns.rb <file containing ip>"
	puts "File must contain one ip on each line"
	exit
end

require 'mechanize'
puts "\n***	Passive dns from virustotal using own api key			***"
puts "***	This script will query against virustotal 4 times per minute	***" 
puts "***	as I am using a public api key when I wrote it			***\n\n"
 
key = '' #enter your api key here
ip_list = File.readlines(ARGV[0]).each{|z| z.chomp!}
agent = Mechanize.new

count = 0
total = 0
ip_list.each do |ip|
	if count < 4
		puts "\n---------- start of #{ip} ----------\n"
		page = agent.get("http://www.virustotal.com/vtapi/v2/ip-address/report?ip=#{ip}&apikey=#{key}")
		page.body.split(',').each do |x|
			x.gsub!('{', '')
			x.gsub!('"', '')  
			x.gsub!('}', '')  
			x.gsub!('[', "\n ")  
			x.gsub!(']', '')
			x.gsub!('resolutions:', '')
			x.gsub!(/^asn:/, ' asn:')  
			puts x
		end  
		puts "\n---------- end of #{ip} -----------\n"
		count += 1
	else
		sleep 60
		count = 0
		redo
	end
end
