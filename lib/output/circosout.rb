module Prenus
module Output

class Circosout < Baseout

	#
	# Initialises the Circosout class into an object
	#
	# @return [Object]
	#     Returns the Circosout object
	#
	# @input
	#    events	 - the hash object with all the vulnerability events within it - @see Nessusin#import_nessus_files
	#    hosts   - the hash object with all the hosts within it - @see Nessusin#import_nessus_files
	#    options - the hash object with the configuration objections within it. These options include the output folder etc, and are used within many of the methods below
	#
	# @example
	#    object = Prenus::Output::Circosout(events,hosts,options)
	#
	#    The output of this is then to be used with Circos (http://circos.ca/)
	#     GD was a REAL bitch to get going on OS X 10.7
	#
	#     From within the circos-tools/tools/tableviewer/ folder
	#     i.e. cat prenus.circus | bin/parse-table -conf samples/parse-table-01.conf | bin/make-conf -dir data
	#
	#     From within the same folder, but going back to the circos perl script
	#     i.e. ../../circos-folder/bin/circos -conf etc/circos.conf -outputfile output.png
	#     This should drop the file into img/ folder. 
	#    
	#     The above is a bit fickle, so the etc/circos.conf and the /data file should all be within the tableviewer/ folder, and just call back out to the circos perl script
	#
	def initialize(events,hosts,options)
		super
	end

	#
	# Run the Circosout class - this will generate a simple table file, which can be used by circos' tableviewer tool
	#
	# @return
	#    Returns nothing
	#
	# @example
	#   object.run
	#
	def run
		# File.open(@options[:outputdir] + "/prenus.circos", 'w') do |f|

		included_events = []

		line = "data\t"
		@events.each_with_index do |(k,v),index|
			unless @options[:filter].nil?
				next unless @options[:filter].include?(k.to_s)
			end
			# The graphs were getting too mental, so I hard coded to ignore everything except High and Critical findings
			next if v[:severity].to_i < @options[:severity].to_i

			included_events << k
			line += k.to_s
			line += "\t" unless index == @events.count - 1
		end

		#f.puts line
		@oFile.syswrite line + "\n"

		@hosts.each_with_index do |(k,v),index|
			line = @hosts[k][:ip].to_s + "\t"
			atleastone = false

			included_events.each_with_index do |ev,index2|
				got_value = false
				@events.each do |evkey,evval|
					if evkey == ev
						evval[:ports].each do |p,hs|
							next if got_value == true
							if hs[:hosts].has_key?(k)
								line += "1"
								line += "\t" unless index2 == included_events.count - 1
								got_value = true
								atleastone = true
							else
								line += "0"
								line += "\t" unless index2 == included_events.count - 1
								got_value = true
							end
						end
					end
				end
			end

			#f.puts line unless atleastone == false
			@oFile.syswrite line + "\n" unless atleastone == false
		end

		# end

	end

end

end end
