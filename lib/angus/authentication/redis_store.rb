require 'json'
require 'redis'

module Angus
  module Authentication

    class RedisStore

      def initialize(settings)
        @settings = settings
      end

      def has_key?(key)
        redis.exists(key)
      end

      def save_session_data(key, data, ttl)
        redis.set(key, JSON(data))
        redis.expire(key, ttl)
      end

      def get_session_data(key)
        JSON(redis.get(key) || {})
      end

      def redis
        @redis ||= Redis.new(@settings)
      end

    end

  end
end