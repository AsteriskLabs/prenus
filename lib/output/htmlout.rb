module Prenus
module Output

class Htmlout < Baseout

	#
	# Initialises the Htmlout class into an object
	#
	# @return [Object]
	#    Returns the Htmlout object
	#
	# @input
	#    events	 - the hash object with all the vulnerability events within it - @see Nessusin#import_nessus_files
	#    hosts   - the hash object with all the hosts within it - @see Nessusin#import_nessus_files
	#    options - the hash object with the configuration objections within it. These options include the output folder etc, and are used within many of the methods below
	#
	# @example
	#    object = Prenus::Output::Htmlout(events,hosts,options)
	#
	def initialize(events, hosts, options)
		super

		#prepare folder - copy js files
		FileUtils.cp(File.expand_path($root_dir + '/lib/js/jquery.min.js'), options[:output] + '/jquery.min.js')
		FileUtils.cp(File.expand_path($root_dir + '/lib/js/highcharts.js'), options[:output] + '/highcharts.js')
		FileUtils.cp(File.expand_path($root_dir + '/lib/js/jquery.dataTables.js'), options[:output] + '/jquery.dataTables.js')

		#prepare folder - copy css files
		FileUtils.cp(File.expand_path($root_dir + '/lib/css/table.css'), options[:output] + '/table.css')

		#prepare folder - copy image files
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/back_disabled.png'), options[:output] + '/back_disabled.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/back_enabled.png'), options[:output] + '/back_enabled.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/back_enabled_hover.png'), options[:output] + '/back_enabled_hover.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/forward_disabled.png'), options[:output] + '/forward_disabled.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/forward_enabled.png'), options[:output] + '/forward_enabled.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/forward_enabled_hover.png'), options[:output] + '/forward_enabled_hover.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/sort_asc.png'), options[:output] + '/sort_asc.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/sort_asc_disabled.png'), options[:output] + '/sort_asc_disabled.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/sort_both.png'), options[:output] + '/sort_both.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/sort_desc.png'), options[:output] + '/sort_desc.png')
		FileUtils.cp(File.expand_path($root_dir + '/lib/images/sort_desc_disabled.png'), options[:output] + '/sort_desc_disabled.png')

	end

	#
	# Run the Htmlout class - this will generate all the necessary HTML files and copy other dependencies (JS/CSS/PNGs) to the target folder
	#
	# @return
	#    Returns nothing
	#
	# @example
	#   object.run
	#
	def run
		self.print_hosts # generate all the host_*.html files
		self.print_index # generate the index.html file
		self.print_vulns # generate all the vuln_*.html files
		self.print_vuln_overview # generate the vuln_overview.html file
	end

	#
	# Generate the index.html file, outputting it to the nominated output directory + /index.html
	#    @see @options[:output]
	#
	# @return
	#     Returns nothing
	#
	# @example
	#     print_index
	#
	def print_index
		File.open(@options[:output] + "/index.html",'w') do |f|
			html_header(f,"Home")

			bar_js(f,"bar_graph","Top 20 Hosts",@hosts.sort_by{|k,v| v[:total_excl_info]}.reverse.take(20))

			crit_total = 0
			high_total = 0
			med_total = 0
			low_total = 0

			@events.each do |k,v|
				crit_total += 1 if v[:severity] == 4
				high_total += 1 if v[:severity] == 3
				med_total += 1 if v[:severity] == 2
				low_total += 1 if v[:severity] == 1
			end

			pie_data = []
			pie_data << ['Low',low_total.to_i,'green'] if @options[:severity] <= 1 and low_total.to_i > 0
			pie_data << ['Medium',med_total.to_i,'orange'] if @options[:severity] <= 2 and med_total.to_i > 0
			pie_data << ['High',high_total.to_i,'red'] if @options[:severity] <= 3 and high_total.to_i > 0
			pie_data << ['Critical',crit_total.to_i,'purple'] if @options[:severity] <= 4 and crit_total.to_i > 0

			pie_js(f,"pie_graph","Unique Vulnerability Breakdown","Unique Vuln Breakdown",pie_data,"document.location.href = 'vuln_overview.html';")

			crit_total = 0
			high_total = 0
			med_total = 0
			low_total = 0

			@hosts.each do |id,values|
				crit_total += values[:crit].to_i
				high_total += values[:high].to_i
				med_total += values[:med].to_i
				low_total += values[:low].to_i
			end

			pie_data = []
			pie_data << ['Low',low_total.to_i,'green'] if @options[:severity] <= 1 and low_total.to_i > 0
			pie_data << ['Medium',med_total.to_i,'orange'] if @options[:severity] <= 2 and med_total.to_i > 0
			pie_data << ['High',high_total.to_i,'red'] if @options[:severity] <= 3 and high_total.to_i > 0
			pie_data << ['Critical',crit_total.to_i,'purple'] if @options[:severity] <= 4 and crit_total.to_i > 0

			pie_js(f,"pie_graph2","Total Vunerability Breakdown","Total Vuln Breakdown",pie_data,"document.location = href= 'vuln_overview.html';")

			target_lookup = "var target_lookup = {"
			@hosts.each_with_index do |host,index|
				if host[1][:hostname] == ""
					target_lookup += "'" + host[1][:ip] + "'"
				else
					target_lookup += "'" + host[1][:hostname] + " (" + host[1][:ip] + ")" + "'"
				end
				target_lookup += ": " + host[0].to_s
				target_lookup += "," unless index == @hosts.length - 1
			end
			target_lookup += "}"

			f.puts target_lookup

			close_html_header(f)

			unless @options[:indexfile].nil?
				IO.copy_stream(File.open(@options[:indexfile]),f)
			end

			body = '<div style="width: 800px; margin-left: auto; margin-right: auto; padding-top: 30px;">'
			body += '<div id="pie_graph" style="min-width: 375px; height: 375px; margin: 0 auto; float: left"></div>'
			body += '<div id="pie_graph2" style="min-width: 375px; height: 375px; margin: 0 auto; float: left"></div>'
			body += '</div>'
			body += '<div style="clear: both;"></div>'
			body += '<div id="bar_graph" style="min-width: 400px; height: 900px; margin: 0 auto"></div>'

			body += '<div id="allhosts"><h3>All Hosts</h3>'

			ips = []
			@hosts.each do |host|
				ips << host[1][:ip]
			end

			body += '<table id="hosts_table" class="display"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Vulnerability Count (Low to Critical)</th></tr></thead><tbody>'
			ips.sort_by{|ip| ip.split('.').map{|octet| octet.to_i}}.each do |ip|
				@hosts.select{|k,v| v[:ip] == ip}.each do |k,v|
					tmp_actual_v_count = 0
					tmp_actual_v_count += v[:low].to_i if @options[:severity] <= 1 and v[:low].to_i > 0
					tmp_actual_v_count += v[:med].to_i if @options[:severity] <= 2 and v[:med].to_i > 0
					tmp_actual_v_count += v[:high].to_i if @options[:severity] <= 3 and v[:high].to_i > 0
					tmp_actual_v_count += v[:crit].to_i if @options[:severity] <= 4 and v[:crit].to_i > 0
					body += '<tr><td>'
					if tmp_actual_v_count > 0
						body += '<a href="host_' + k.to_s + '.html">' + ip + '</a>'
					else
						body += ip
					end
					body += '</td><td>' + v[:hostname] + '</td><td>' + v[:os] + '</td><td>' + v[:total_excl_info].to_s + '</td></tr>'
				end
			end
			body += '</tbody></table>'

			body += '<script>$(document).ready(function() { $(\'#hosts_table\').dataTable({"bPaginate": false}); });</script>'

			body_text(f,body)

			close_all(f)

		end

	end

	#
	# Generate the vuln_overview.html file, outputting it to the nominated output directory + /vuln_overview.html
	#    @see @options[:output]
	#
	# @return
	#    Returns nothing
	#
	# @example
	#    print_vuln_overvire
	#
	def print_vuln_overview
		File.open(@options[:output] + "/vuln_overview.html", 'w') do |f|
			html_header(f,"Vulns Overview")

			close_html_header(f)

			body = '<a href="index.html">Home</a><br /><div id="vulns"><h2>Vulnerabilities</h2>'

			body += '<table id="vulns_table" class="display"><thead><tr><th>Nessus ID</th><th>Severity</th><th>Name</th><th>Family</th><th>Ports</th><th>Number of impacted hosts</th></tr></thead><tbody>'
			@events.each do |k,v| 
				next if v[:severity].to_i < @options[:severity].to_i
				body += '<tr><td><a href="vuln_' + k.to_s + '.html">' + k.to_s
				body += '</a></td><td>' + v[:severity].to_s + '<td>' + v[:plugin_name] + '</td>'
				body += '<td>' + v[:family].to_s + '</td><td>'
				impacted_hosts = []
				v[:ports].each_with_index do |(k2,v2),index|
					body += k2.to_s 
					body += ", " unless index == v[:ports].length - 1
					v2[:hosts].each do |h,w|
						impacted_hosts << h
					end
				end
				impacted_hosts.uniq!
				body += '</td><td>' + impacted_hosts.count.to_s + '</td></tr>'
			end
			body += '</tbody></table>'

			body += '<script>$(document).ready(function() { $(\'#vulns_table\').dataTable({"bPaginate": false,"aaSorting": [[1,"desc"],[5,"desc"]]}); });</script>'
			body_text(f,body)

			close_all(f)
		end
	end

	#
	# Generates the various vuln_*.html files, outputting them to the nominated output directory
	#    @see @options[:output]
	#
	# @return
	#     Returns nothing
	#
	# @example
	#    print_vulns
	#
	def print_vulns
		@events.each do |id,values|
			next if values[:severity].to_i < @options[:severity].to_i
			File.open(@options[:output] + "/vuln_" + id.to_s + ".html", 'w') do |f|
				html_header(f,id.to_s)

				close_html_header(f)

				body = '<a href="index.html">Home</a><br /><div id="vuln"><div id="overview">Nessus ID: ' + id.to_s + '<br />Name: ' + values[:plugin_name] + '<br />Severity: ' + values[:severity].to_s + '<br />Family: ' + values[:family] + '<br />Ports: '
				impacted_hosts = []
				values[:ports].each_with_index {|(k,v),index|
					body += k.to_s
					v[:hosts].each do |h,w|
						impacted_hosts << h
					end
					body += ", " unless index == values[:ports].length - 1
				}
			  	body += '<br /><br />Synopsis:<br />' + values[:synopsis] + '<br /><br />Description:<br />' + values[:description] + '<br /><br />Solution:<br />' + values[:solution] + '<br /><br />See Also:<br />'
				values[:see_also].each do |val|
					val.split("\n").each do |val2|
						body += '<a href="' + val2 + '">' + val2 + '</a><br />'
					end
				end
				body +='<br /><br />CVE: ' + values[:cve].to_s + '<br />CVSS Base Score: ' + values[:cvss_base_score].to_s + '<br />CVSS Vector: ' + values[:cvss_vector].to_s + '</div>'
				body += '</div>'

				body += '<div id="hosts"><h2>Hosts</h2>'

				body += '<table id="hosts_table" class="display"><thead><tr><th>Host IP</th><th>Hostname</th><th>OS</th><th>Port</th><th>Result</th></tr></thead><tbody>'

				impacted_hosts.uniq.each do |host|
					
					values[:ports].each{|k,v|
						v[:hosts].each do |h,w|
							if h == host
								body += '<tr><td><a href="host_' + host.to_s + '.html">' + @hosts[host][:ip] + '</a></td><td>' + @hosts[host][:hostname] + '</td><td>' + @hosts[host][:os] + '</td>'
								body += '<td>' + k.to_s + '</td><td>' + w.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />\n") + "</td></tr>\n"
							end
						end
					}
				end

				body += '</tbody></table>'

				body += '<script>$(document).ready(function() { $(\'#hosts_table\').dataTable({"bPaginate": false,"aaSorting": [[0,"asc"]]}); });</script>'

				body_text(f,body)

				close_all(f)
			end
		end
	end


	#
	# Generates the various host_*.html files, outputting them to the nominated output directory
	#    @see @options[:output]
	#
	# @return
	#     Returns nothing
	#
	# @example
	#    print_hosts
	#
	def print_hosts
		@hosts.each do |id,values|
			File.open(@options[:output] + "/host_" + id.to_s + ".html", 'w') do |f|

				html_header(f,values[:ip])

				if values[:total_excl_info] == 0
					pie_js(f,"pie_graph","Criticality Breakdown","Criticality Breakdown",[['Informational ONLY',values[:info].to_i,'blue']])					
				else
					pie_data = []
					pie_data << ['Low',values[:low].to_i,'green'] if @options[:severity] <= 1 and values[:low].to_i > 0
					pie_data << ['Medium',values[:med].to_i,'orange'] if @options[:severity] <= 2 and values[:med].to_i > 0
					pie_data << ['High',values[:high].to_i,'red'] if @options[:severity] <= 3 and values[:high].to_i > 0
					pie_data << ['Critical',values[:crit].to_i,'purple'] if @options[:severity] <= 4 and values[:crit].to_i > 0
					pie_js(f,"pie_graph","Criticality Breakdown","Criticality Breakdown",pie_data,"document.location.href = '#' + event.point.name;")
				end

				close_html_header(f)

				body = '<a href="index.html">Home</a><br /><div id="host"><div id="overview">Hostname: ' + values[:hostname] + '<br />IP: ' + values[:ip] + '<br />OS: ' + values[:os] + '<br /></div>'
				body += '<div id="graphs"><h2>Overview</h2>'
				body += '<div id="pie_graph" style="min-width: 400px; height: 400px; margin: 0 auto"></div>'
				body += '</div>'

				body += '<div id="vulns"><h2>Vulnerabilities</h2>'


				if @options[:severity] <= 4 and values[:crit].to_i > 0
					body += '<div id="critical"><a name="Critical"></a><h3>Critical</h3>'

					body += '<table id="critical_table" class="display"><thead><tr><th>Nessus ID</th><th>Name</th><th>Synopsis</th><th>Result</th><th>Family</th><th>Port</th></tr></thead><tbody>'
					@events.sort_by{|k,v| v[:port].to_s}.each do |vuln_id,vuln_data|
						vuln_data[:ports].each {|k,v|

							v[:hosts].each do |h,v2|
								if h == id and vuln_data[:severity] == 4
									body += '<tr><td><a href="vuln_' + vuln_id.to_s + '.html">' + vuln_id.to_s + '</a></td><td>' + vuln_data[:plugin_name] + '</td><td>' + vuln_data[:synopsis] + '</td><td>' + v2.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />") + '</td><td>' + vuln_data[:family] + '</td><td>' + k.to_s + '</td></tr>'
								end
							end
						}
					end
					body += '</tbody></table></div>'
				end

				if @options[:severity] <= 3 and values[:high].to_i > 0

					body += '<div id="high"><a name="High"></a><h3>High</h3>'

					body += '<table id="high_table" class="display"><thead><tr><th>Nessus ID</th><th>Name</th><th>Synopsis</th><th>Result</th><th>Family</th><th>Port</th></tr></thead><tbody>'
					@events.sort_by{|k,v| v[:port].to_s}.each do |vuln_id,vuln_data|
						vuln_data[:ports].each {|k,v|
							v[:hosts].each do |h,v2|
								if h == id and vuln_data[:severity] == 3
									body += '<tr><td><a href="vuln_' + vuln_id.to_s + '.html">' + vuln_id.to_s + '</a></td><td>' + vuln_data[:plugin_name] + '</td><td>' + vuln_data[:synopsis] + '</td><td>' + v2.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />") + '</td><td>' + vuln_data[:family] + '</td><td>' + k.to_s + '</td></tr>'
								end
							end
						}
					end
					body += '</tbody></table></div>'
				end

				if @options[:severity] <= 2 and values[:med].to_i > 0

					body += '<div id="medium"><a name="Medium"></a><h3>Medium</h3>'

					body += '<table id="medium_table" class="display"><thead><tr><th>Nessus ID</th><th>Name</th><th>Synopsis</th><th>Result</th><th>Family</th><th>Port</th></tr></thead><tbody>'
					@events.sort_by{|k,v| v[:port].to_s}.each do |vuln_id,vuln_data|
						vuln_data[:ports].each {|k,v|
							v[:hosts].each do |h,v2|
								if h == id and vuln_data[:severity] == 2
									body += '<tr><td><a href="vuln_' + vuln_id.to_s + '.html">' + vuln_id.to_s + '</a></td><td>' + vuln_data[:plugin_name] + '</td><td>' + vuln_data[:synopsis] + '</td><td>' + v2.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />") + '</td><td>' + vuln_data[:family] + '</td><td>' + k.to_s + '</td></tr>'
								end
							end
						}
					end
					body += '</tbody></table></div>'

				end

				if @options[:severity] <= 1 and values[:low].to_i > 0

					body += '<div id="low"><a name="Low"></a><h3>Low</h3>'

					body += '<table id="low_table" class="display"><thead><tr><th>Nessus ID</th><th>Name</th><th>Synopsis</th><th>Result</th><th>Family</th><th>Port</th></tr></thead><tbody>'
					@events.sort_by{|k,v| v[:port].to_s}.each do |vuln_id,vuln_data|
						vuln_data[:ports].each {|k,v|
							v[:hosts].each do |h,v2|
								if h == id and vuln_data[:severity] == 1
									body += '<tr><td><a href="vuln_' + vuln_id.to_s + '.html">' + vuln_id.to_s + '</a></td><td>' + vuln_data[:plugin_name] + '</td><td>' + vuln_data[:synopsis] + '</td><td>' + v2.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />") + '</td><td>' + vuln_data[:family] + '</td><td>' + k.to_s + '</td></tr>'
								end
							end
						}
					end
					body += '</tbody></table></div>'
				end

				if @options[:severity] <= 0 and values[:info].to_i > 0

					body += '<div id="informational"><a name="Informational"></a><h3>Informational</h3>'

					body += '<table id="informational_table" class="display"><thead><tr><th>Nessus ID</th><th>Name</th><th>Synopsis</th><th>Result</th><th>Family</th><th>Port</th></tr></thead><tbody>'
					@events.sort_by{|k,v| v[:port].to_s}.each do |vuln_id,vuln_data|
						vuln_data[:ports].each {|k,v|
							v[:hosts].each do |h,v2|
								if h == id and vuln_data[:severity] == 0
									body += '<tr><td><a href="vuln_' + vuln_id.to_s + '.html">' + vuln_id.to_s + '</a></td><td>' + vuln_data[:plugin_name] + '</td><td>' + vuln_data[:synopsis] + '</td><td>' + v2.to_s.gsub(/<\/?[^>]*>/, "").gsub("\n","<br />") + '</td><td>' + vuln_data[:family] + '</td><td>' + k.to_s + '</td></tr>'
								end
							end
						}
					end
					body += '</tbody></table></div>'
				end


				body += "<script>$(document).ready(function() {\n ";
				body += "$('#critical_table').dataTable({\"bPaginate\": false});\n" if @options[:severity] <= 4
				body += "$('#high_table').dataTable({\"bPaginate\": false});\n" if @options[:severity] <= 3
				body += "$('#medium_table').dataTable({\"bPaginate\": false});\n" if @options[:severity] <= 2
				body += "$('#low_table').dataTable({\"bPaginate\": false});\n" if @options[:severity] <= 1
				body += "$('#informational_table').dataTable({\"bPaginate\": false});\n" if @options[:severity] <= 0
				body += "});</script>"

				body += '</div></div>'

				body_text(f,body)

				close_all(f)
			end
		end

	end

	#
	# Prints the universal HTML header into the nominated output file
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp    - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#    title - the title field which is printed as the HTML title
	#
	# @example
	#    File.open(@options[:output] + "/file.html", 'w') do |f|
	#			html_header(f,"Title")
	#    end
	#
	def html_header(fp,title)
		fp.puts <<-eos

		<!DOCTYPE HTML>
		<html>
			<head>
				<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
				<title>#{title}</title>

				<script type="text/javascript" src="jquery.min.js"></script>
				<script type="text/javascript" src="jquery.dataTables.js"></script>
				<style type="text/css" title="currentStyle">
					@import "table.css";
				</style>
				<script type="text/javascript">
				jQuery.fn.dataTableExt.aTypes.unshift(
				    function ( sData )
				    {
				        if (/^.*\\d{1,3}[\\.]\\d{1,3}[\\.]\\d{1,3}[\\.]\\d{1,3}.*$/.test(sData)) {
				            return 'ip-address';
				        }
				        return null;
				    }
				);

				jQuery.extend( jQuery.fn.dataTableExt.oSort, {
				    "ip-address-pre": function ( a ) {
				    	var b = a.replace(/<.*?>/g,"");
				        var m = b.split("."), x = "";
				 
				        for(var i = 0; i < m.length; i++) {
				            var item = m[i];
				            if(item.length == 1) {
				                x += "00" + item;
				            } else if(item.length == 2) {
				                x += "0" + item;
				            } else {
				                x += item;
				            }
				        }
				 
				        return x;
				    },
				 
				    "ip-address-asc": function ( a, b ) {
				        return ((a < b) ? -1 : ((a > b) ? 1 : 0));
				    },
				 
				    "ip-address-desc": function ( a, b ) {
				        return ((a < b) ? 1 : ((a > b) ? -1 : 0));
				    }
				} );
		eos
	end

	#
	# Prints out the closing statements for the universal HTML header into the nominated output file
	#
	# @see def html_header(fp,title)
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#
	# @example
	#    @see html_header's @example
	#
	def close_html_header(fp)
		fp.puts <<-eos
		</script>
			</head>
			<body>
		<script src="highcharts.js"></script>
		eos
	end

	#
	# Prints out miscellanrous HTML text into the nominated output file
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp   - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#    text - the text to print out to the output file
	#
	# @example
	#  File.open(@options[:output] + "/file.html",'w') do |f|
	#  		tmpline = "Sometext<br />"
	#       tmpline += "Some more text here<br />"
	#       body_text(f,tmpline)
	#  end
	#
	def body_text(fp,text)
		fp.puts text
	end

	#
	# Closes out the HTML of the page in the nominated output file
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#
	# @example
	#    @see html_header's @example
	#
	def close_all(fp)
		fp.puts <<-eos
				</body>
			</html>
		eos
	end

	#
	# Prints the Highcharts javascript for a bar graph into the nominated output file
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp       - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#    renderto - the highchart renderTo parameter (which is then referenced in the html's div id)
	#    title    - the highchart's title
	#    data     - a hash of hosts data @see Nessusin#import_nessus_files
	#
	# @example
	#  File.open(@options[:output] + "/file.html",'w') do |f|
	#     bar_js(f,"bargraph1","Some title",{0 => {:hostname => 'hostname',:ip => 'ip'}})
	#
	#     body_text(f,"<div id='bargraph1'>")
	#  end
	#
	def bar_js(fp,renderto,title,data)
		fp.puts <<-eos
		$(function () {
		    var chart;
		    $(document).ready(function() {
		        chart = new Highcharts.Chart({
		        	credits: {
		        		enabled: false
		        	},
		            chart: {
		                renderTo: '#{renderto}',
		                type: 'bar'
		            },
		            title: {
		                text: '#{title}'
		            },
		            xAxis: {
				categories: [
		eos

		data.each_with_index do |entry,index|
			tmpline = "'"
			if entry[1][:hostname] == ""
				tmpline += entry[1][:ip]
			else
				tmpline += entry[1][:hostname] + " (" + entry[1][:ip] + ")"
			end
			tmpline += "'"
			tmpline += "," unless index == data.length - 1
			fp.puts tmpline
		end
		fp.puts <<-eos
		]
            },
            yAxis: {
                min: 0,
                allowDecimals: false,
                title: {
                    text: 'Findings'
                }
            },
            legend: {
                backgroundColor: '#FFFFFF',
                reversed: true
            },
            tooltip: {
                formatter: function() {
                    return ''+
                        this.series.name +': '+ this.y +'';
                }
            },
            plotOptions: {
                series: {
                    stacking: 'normal',
                    //threshold: 1,
                    dataLabels: {
                    	enabled: true,
                    	color: '#000000',
                    	x: 0,
                    	align: 'center',
                    	formatter: function() {
                    		if (this.y !=0) {
                    			return this.y;
                    		}
                    	}
                    },
                    events: {
                    	click: function(event) {
                    		//alert(target_lookup[event.point.category])
                    		document.location.href = 'host_' + target_lookup[event.point.category] + '.html#' + event.currentTarget.name;
                    		//console.log(event)
                    	}
                    }
                }
            },
                series: [
		eos

		if @options[:severity] <= 4
			fp.puts "{name: 'Critical',"
			fp.puts "color: 'purple',"
			tmpline = "data: ["

			data.each_with_index do |entry,index|
				tmpline += entry[1][:crit].to_s
				tmpline += "," unless index == data.length - 1
			end
			tmpline += "]"
			fp.puts tmpline
			fp.puts "}"
		end

		if @options[:severity] <= 3
			fp.puts ",{name: 'High',"
			fp.puts "color: 'red',"
			tmpline = "data: ["

			data.each_with_index do |entry,index|
				tmpline += entry[1][:high].to_s
				tmpline += "," unless index == data.length - 1
			end
			tmpline += "]"
			fp.puts tmpline
			fp.puts "}"
		end

		if @options[:severity] <= 2
			fp.puts ",{name: 'Medium',"
			fp.puts "color: 'orange',"
			tmpline = "data: ["

			data.each_with_index do |entry,index|
				tmpline += entry[1][:med].to_s
				tmpline += "," unless index == data.length - 1
			end
			tmpline += "]"
			fp.puts tmpline
			fp.puts "}"
		end

		if @options[:severity] <= 1

			fp.puts ",{name: 'Low',"
			fp.puts "color: 'green',"
			tmpline = "data: ["

			data.each_with_index do |entry,index|
				tmpline += entry[1][:low].to_s
				tmpline += "," unless index == data.length - 1
			end
			tmpline += "]"
			fp.puts tmpline
			fp.puts "}"
		end

		fp.puts <<-eos
						
		            ]
		        });
		    });
		    
		});
		eos
	end

	#
	# Prints the Highcharts javascript for a pie graph into the nominated output file
	#
	# @return
	#    Returns nothing
	#
	# @input
	#    fp            - the file pointer (which should be opened already by the calling method) which this method prints its output into
	#    renderto      - the highchart renderTo parameter (which is then referenced in the html's div id)
	#    title         - the highchart's title
	#    seriesname    - the highchart's series name
	#    series        - an array of array's with pie piece names and values
	#    clickfunction - an optional string which is then used as the click event for a pie piece
	#
	# @example
	#   File.open(@options[:output] + "/file.html",'w') do |f|
	#      pie_js(f,"pie_graph","Vuln Breakdown","Vuln Breakdown",[['Low',2],['Medium',5],['High',3]],"document.location.href = 'vuln_overview.html#' + event.point.name;")
	#
	#      body_text(f,"<div id='pie_graph'>")
	#   end
	#
	def pie_js(fp,renderto,title,seriesname,series,clickfunction = nil)
		fp.puts <<-eos
		$(function () {
		    var chart;
		    $(document).ready(function() {
		        chart = new Highcharts.Chart({
		        	credits: {
		        		enabled: false
		        	},
		            chart: {
		                renderTo: '#{renderto}',
		                plotBackgroundColor: null,
		                plotBorderWidth: null,
		                plotShadow: false
		            },
		            title: {
		                text: '#{title}'
		            },
		            tooltip: {
		                formatter: function() {
		                    return '<b>'+ this.point.name +'</b>: '+ Math.round(this.percentage) +' %';
		                }
		            },
		            plotOptions: {
		                pie: {
		                	size: '60%',
		                    allowPointSelect: true,
		                    cursor: 'pointer',
		                    dataLabels: {
		                        enabled: true,
		                        color: '#000000',
		                        connectorColor: '#000000',
		                        formatter: function() {
		                            return '<b>'+ this.point.name +'</b>: '+ this.y;
		                        },
		                        distance: 20
		                    }
		eos

		unless clickfunction.nil?
			fp.puts ',events: { click: function(event) { ' + clickfunction + '} }'
		end 

		fp.puts <<-eos
                }
            },
            series: [{
                type: 'pie',
                name: '#{seriesname}',
                data: [
		eos
		series.each_with_index do |val,index|
			tmpline =  "\t\t\t{name: '" + val[0] + "', y: " + val[1].to_s + ", color: '" + val[2] + "'}"
			tmpline += "," unless index == series.length - 1
			fp.puts tmpline
		end

		fp.puts <<-eos
		                ]
		            }]
		        });
		    });
		    
		});
		eos
		
	end

end

end end