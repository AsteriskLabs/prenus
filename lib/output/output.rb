module Prenus
module Output

	class Baseout

		@events = {} 	#instance variable of all vulnerability events
		@hosts = {}  	#instance variable of all the hosts
		@options = {}	#instance variable of the options hash, this inclues all the configuration settings @see Htmlout#initialize
		@oFile = nil    #the output file

		#
		# This is the super-class that all output classes should inherent
		#  @see Htmlout#initialize
		#
		def initialize(events, hosts, options)
			@events = events
			@hosts = hosts
			@options = options

			if @options[:type] == "html" #Therefore, the output should be a folder name, not a file

				@options[:output] = "." if @options[:output].nil?

				#Check if the output dir exists
				Dir.mkdir(@options[:output]) unless File.exists?(@options[:output])
			else
				@oFile = File.new(@options[:output],'w') unless @options[:output].nil?
				@oFile = STDOUT if @oFile.nil?
			end

		end

		#
		# All inherented classes should implement a run method
		#   @see Htmlout#run
		#
		def run

		end
	end

end end