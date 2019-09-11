Gem::Specification.new do |s|
  s.name          = 'logstash-filter-mtools'
  s.version       = '0.1.1'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'The party number parser.'
  s.description   = 'This filter allow to parse party number values from Protey GMSC cdrs and put it in a nested structure.'
  s.homepage      = 'http://berg.sh'
  s.authors       = ['Alexey Polyakov']
  s.email         = 'berghauz@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir["lib/**/*","spec/**/*","*.gemspec","*.md","CONTRIBUTORS","Gemfile","LICENSE","NOTICE.TXT", "vendor/jar-dependencies/**/*.jar", "vendor/jar-dependencies/**/*.rb", "VERSION", "docs/**/*"]
   # Tests
  #s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", '>= 1.60', '<= 2.99'
  s.add_runtime_dependency "ipaddr"

  s.add_development_dependency 'logstash-devutils', '>= 1.3'
end
