lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'angus/authentication/version'

Gem::Specification.new do |spec|
  spec.name           = 'angus-authentication'
  spec.version        = Angus::Authentication::VERSION
  spec.platform       = Gem::Platform::RUBY
  spec.authors        = ['Adrian Gomez']
  spec.summary        = 'Offers authentication for rack applications.'
  spec.email          = %w[angus@moove-it.com]
  spec.homepage       = 'https://github.com/Moove-it/angus-authentication'
  spec.license        = 'MIT'

  spec.files           = Dir.glob('{lib}/**/*')

  spec.add_dependency('rack', '~> 1.5')
  spec.add_dependency('redis')
  spec.add_dependency('bcrypt', '~> 3')
  spec.add_dependency('connection_pool', '~> 1.2')

  spec.add_development_dependency('rake', '~> 10.1')
  spec.add_development_dependency('rspec', '~> 2.14')
  spec.add_development_dependency('rack-test', '~> 0.6')
  spec.add_development_dependency('mock_redis')
  spec.add_development_dependency('timecop')
  spec.add_development_dependency('simplecov', '~> 0.7')
  spec.add_development_dependency('simplecov-rcov')
  spec.add_development_dependency('simplecov-rcov-text')
  spec.add_development_dependency('ci_reporter')
end