require 'json'
require 'redis'

module Angus
  module Authentication

    class RedisStore

      DEFAULT_NAMESPACE = ''

      def initialize(settings)
        settings = settings.dup
        @namespace = settings.delete(:namespace) || DEFAULT_NAMESPACE
        @settings = settings
      end

      def has_key?(key)
        redis.exists(add_namespace(key))
      end

      def save_session_data(key, data, ttl)
        redis.set(add_namespace(key), JSON(data))
        redis.expire(add_namespace(key), ttl)
      end

      def get_session_data(key)
        JSON(redis.get(add_namespace(key)) || {})
      end

      def redis
        @redis ||= Redis.new(@settings)
      end

      def add_namespace(key)
        "#@namespace.angus-authentication-provider.#{key}"
      end

    end

  end
end