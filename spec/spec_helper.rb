$: << (File.dirname(__FILE__))

require 'bundler/setup'

require 'simplecov'
SimpleCov.start

require 'rspec'
require 'simplecov-rcov'
require 'simplecov-rcov-text'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  SimpleCov::Formatter::RcovFormatter,
  SimpleCov::Formatter::RcovTextFormatter
]

Dir[File.dirname(__FILE__) + '/support/**/*.rb'].each { |f| require f }

require 'redis'
require 'mock_redis'

RSpec.configure do |config|

  redis = MockRedis.new

  config.before do
    Redis.stub(:new => redis)
  end

  config.after do
    redis.flushdb
  end

end