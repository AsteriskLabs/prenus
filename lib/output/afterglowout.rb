module Prenus
module Output

class Afterglowout < Baseout

	#
	# Initialises the Afterglowout class into an object
	#
	# @return [Object]
	#     Returns the Afterglowout object
	#
	# @input
	#    events	 - the hash object with all the vulnerability events within it - @see Nessusin#import_nessus_files
	#    hosts   - the hash object with all the hosts within it - @see Nessusin#import_nessus_files
	#    options - the hash object with the configuration objections within it. These options include the output folder etc, and are used within many of the methods below
	#
	# @example
	#    object = Prenus::Output::Afterglowout(events,hosts,options)
	#
	#    The output of this is then to be used with afterglow.pl (http://afterglow.sourceforge.net/)
	#     i.e. cat prenus.glow | ./afterglow.pl -t -c premus.properties | neato -v -Tpng -Gnormalize=true -Goutputorder="edgesfirst" -o test.png
	#
	def initialize(events,hosts,options)
		super
	end

	#
	# Run the Afterout class - this will generate a simple CSV file called prenus.glow to the target folder
	#
	# @return
	#    Returns nothing
	#
	# @example
	#   object.run
	#
	def run
		#File.open(@options[:outputdir] + "/prenus.glow", 'w') do |f|
		@events.each do |k,v|
			unless @options[:filter].nil?
				next unless @options[:filter].include?(k.to_s)
			end
			# The graphs were getting too mental, so I hard coded to ignore everything except High and Critical findings
			next if v[:severity].to_i < @options[:severity].to_i
			impacted_hosts = []
			v[:ports].each do |k2,v2|
				v2[:hosts].each do |h,w|
					impacted_hosts << h
				end
			end

			impacted_hosts.uniq.each do |host|
				#f.puts k.to_s + " (" + v[:severity].to_s + ")," + @hosts[host][:ip] + "\n"
				@oFile.syswrite k.to_s + " (" + v[:severity].to_s + ")," + @hosts[host][:ip] + "\n"
			end

		end
		#end

	end


end

end end