# -*- encoding: utf-8 -*-
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
Gem::Specification.new do |s|
  s.name = "prenus"
  s.version = "0.0.10"
  s.authors = ["Christian Frichot"]
  s.date = "2013-01-02"
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
    'rainbow' => '~> 1.1.0',
    'nokogiri' => '~> 1.6.0'
  }.each do |lib, version|
    s.add_runtime_dependency(lib, *version)
  end
  
end