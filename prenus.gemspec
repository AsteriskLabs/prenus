# -*- encoding: utf-8 -*-
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
Gem::Specification.new do |s|
  s.name = "prenus"
  s.version = "0.0.2"
  s.authors = ["Christian Frichot"]
  s.date = "2012-08-20"
  s.description = "Pretty Nessus = Prenus"
  s.email = "xntrik@gmail.com"
  s.extra_rdoc_files = [
    "LICENSE.txt",
    "README.rdoc"
  ]
  s.files = Dir["{lib}/**/*"] + %w[LICENSE.txt README.rdoc]
  s.executables = 'prenus'
  s.homepage = "http://github.com/AsteriskLabs/prenus"
  s.licenses = ["MIT"]
  s.require_paths = ["lib"]
  s.summary = "Prenus - The Pretty Nessus Parser"

  s.required_ruby_version = '>= 1.9.2'
  s.required_rubygems_version = '>= 1.8.0'

  {
    'ruby-nessus' => '~> 1.0.3'
  }.each do |lib, version|
    s.add_runtime_dependency(lib, *version)
  end
  
end