module Prenus
module Input

class Nessusin

	#
	# This class method is used to convert a single (or collection) of .nessus (v2) files into 2 different hashes. events and hosts
	#
	# @return
	#   hosts  - a hash of hashes
	#            {<hostid> => {:ip => <ip>, :hostname => <hostname>, :os => <os>, :info => <number of informational findings>,
	#                          :low => <number of low findings>, :med => <number of medium findings>,
	#                          :high => <number of high findings>, :crit => <number of critical findings>,
	#                          :total => <total number of findings>, :total_excl_info => <total number of findings excluding informational findings>}}
	#   events - a hash of hashes
	#            {<nessus_id> => {:family => <vuln family>, :severity => <severity>, :plugin_name => <plugin name>,
	#                             :synopsis => <synopsis>, :description => <description>, :solution => <solution>, :see_also => <array of solutions>,
	#                             :cvss_base_score => <CVSS base score>, :cve => <CVE ID>, :cvss_vector => <CVSS vector>,
	#                             :ports => {<port string>, :hosts => {<hostid>, :result => <result>}}}
	#
	# @input
	#   options - the hash object with the configuration objections within it. These options include the output folder etc, and are used within many of the methods below
	#
	# @example
	#   hosts, events = Prenus::Input::Nessusin.import_nessus_files(options)
	#
	def self.import_nessus_files(options)
		hosts = {}  #initialise the output hosts hash
		events = {} #initialise the output events hash

		hostid = 0  #initialise the unique hostid

		#take the options[:input] parameter as a search parameter for input files, we don't check if these are .nessus files or anything
		#Dir.glob(options[:input]) do |nessus_file|
		options[:input].each do |nessus_file|

			Nessus::Parse.new(nessus_file) do |scan| #use the awesome ruby-nessus gem

				# in the scan file, iterate over each host
				scan.each_host do |host|
					ip = host.ip || "" #grap the IP
					next if ip == ""   #I've found sometimes if it doesn't have an IP it means its not scanned for whatever reasons .. like a printer
									   # I next here because I've found it easier to just ignore those which weren't scanned

					# Lets check if we want to skip an IP for .. whatever reason
					unless options[:skip].nil?
						next if options[:skip].include?(ip.to_s)
					end

					hostname = host.hostname || "" #grab the hostname
					os = host.os || "" #grab the os
					os = os.gsub(/\n/,"/") # sometimes the OS is split over multiple lines - mange them together .. mange mange

					# Lets check if there's an override array in the config
					unless options[:override].nil?
						# Check for this IP address, as this is the primary key we use for overriding
						ovr = options[:override].detect{|x|x['ip'] == ip.to_s}
						unless ovr.nil?
							os = ovr['os'] unless ovr['os'].nil? # Override the OS
							hostname = ovr['hostname'] unless ovr['hostname'].nil? # Override the hostname
						end
					end

					info = host.informational_severity_count || 0 #grab the number of informational findings
					low = host.low_severity_count || 0 #grab the number of low findings
					med = host.medium_severity_count || 0 #grab the number of medium findings
					high = host.high_severity_count || 0 #grab the number of high findings
					crit = host.critical_severity_count || 0 #grab the number of critical findings

					# add the host into the hosts hash
					# I'm not yet doing any 'unique' validation, although I probably should .. oh so slack
					hosts[hostid] = {:ip => ip, :hostname => hostname, :os => os, :info => info, :low => low, :med => med, :high => high, :crit => crit, :total => info+low+med+high+crit, :total_excl_info => low+med+high+crit}

					# Now lets iterate through each of the findings in this particular host
					host.each_event do |event|

						# If the events hash already has this event, lets just add this hostid to it's hosts array within the ports hash
						if events.has_key?(event.id)

							#Lets check the ports hash
							if events[event.id][:ports].has_key?(event.port.to_s)

								# We'll only add the hostid if the host's not already in the array
								events[event.id][:ports][event.port.to_s][:hosts][hostid] = event.output unless events[event.id][:ports][event.port.to_s][:hosts].include?(hostid)

							#Lets add this new port to this hash	
							else
								events[event.id][:ports][event.port.to_s] = {:hosts => { hostid => event.output}}
							end

						# okay, this event doesn't exist, lets add it to the events hash
						else
							events[event.id] = {
								#:hosts => [hostid],									#start the hosts array
								:family => event.family || "",						#vuln family
								:severity => event.severity || "",					#severity
								:plugin_name => event.plugin_name || "", 			#plugin name
								:synopsis => event.synopsis || "",					#synopsis
								:description => event.description || "",			#description
								:solution => event.solution || "",					#solution
								:see_also => event.see_also || "",					#see also array
								:cvss_base_score => event.cvss_base_score || "",	#CVSS base score
								:cve => event.cve || "",							#CVE
								:cvss_vector => event.cvss_vector || "",			#CVSS vector
								#:port => event.port.to_s || ""						#port
								:ports => {}
							}
							events[event.id][:ports][event.port.to_s] = {:hosts => {hostid => event.output}}
						end
					end

					#increase the unique host id
					hostid += 1
				end
			end
		end

		#sort the events by severity crit, high, med, low, info
		events = events.sort_by{ |k,v| v[:severity]}.reverse

		#return the hosts and the events hashes
		return hosts, events
	end

end

end end