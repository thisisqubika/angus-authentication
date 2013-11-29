require 'connection_pool'
require 'json'
require 'redis'

module Angus
  module Authentication

    class RedisStore

      DEFAULT_NAMESPACE = ''
      REDIS_POOL_SIZE = 10
      REDIS_POOL_TIMEOUT = 5

      def initialize(settings)
        settings = settings.dup
        @namespace = settings.delete(:namespace) || DEFAULT_NAMESPACE
        @pool_size = settings.delete(:pool_size) || REDIS_POOL_SIZE
        @pool_timeout = settings.delete(:pool_timeout) || REDIS_POOL_TIMEOUT
        @settings = settings
      end

      def has_key?(key)
        redis.with { |connection| connection.exists(add_namespace(key)) }
      end

      def save_session_data(key, data, ttl)
        redis.with do |connection|
          connection.set(add_namespace(key), JSON(data))
          connection.expire(add_namespace(key), ttl)
        end
      end

      def get_session_data(key)
        data = redis.with { |connection| connection.get(add_namespace(key)) } || '{}'
        JSON(data)
      end

      def redis
        @redis ||= ConnectionPool.new(pool_settings) { Redis.new(@settings) }
      end

      def pool_settings
        { :size => @pool_size,
          :timeout => @pool_timeout }
      end

      def add_namespace(key)
        "#@namespace.angus-authentication-provider.#{key}"
      end

    end

  end
end