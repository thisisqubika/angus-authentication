require 'digest'
require 'bcrypt'

require_relative 'redis_store'
require_relative 'default_authenticator'

module Angus
  module Authentication

    class Provider

      DEFAULT_ID_TTL = 60 * 60
      DEFAULT_SESSION_TTL = 60 * 60
      DEFAULT_PRIVATE_KEY = 'CHANGE ME!!'

      AUTHENTICATION_HEADER = 'HTTP_AUTHORIZATION'
      BAAS_AUTHENTICATION_HEADER = 'HTTP_X_BAAS_AUTH'
      BAAS_SESSION_HEADER = 'X-Baas-Session-Seed'
      DATE_HEADER = 'HTTP_DATE'
      REQUEST_HEADER = 'REQUEST_METHOD'
      PATH_HEADER = 'PATH_INFO'

      def initialize(settings, env)
        @session_id_ttl = settings[:session_id_ttl] || DEFAULT_ID_TTL
        @session_ttl = settings[:session_ttl] || DEFAULT_SESSION_TTL
        @private_key = settings[:private_key] || DEFAULT_PRIVATE_KEY
        @authenticator = settings[:authenticator] || DefaultAuthenticator.new(@private_key)
        @store = RedisStore.new(settings[:store] || {})
        @excluded_regexps = settings[:excluded_regexps] || []
        @env = env
      end

      def authenticate!
        return unless should_authenticate?

        if has_session?
          authenticate_session
        else
          start_session
        end
      end

      def update_response_header(response)
        return unless should_authenticate?

        headers = response[1]

        session_data = @store.get_session_data(session_id)

        headers[BAAS_SESSION_HEADER] = session_data['key_seed']
      end

      private

      def should_authenticate?
        return true if @excluded_regexps.empty?

        @excluded_regexps.none? { |regexp| request_path.match(regexp) }
      end

      def request_path
        @env[PATH_HEADER]
      end

      def has_session?
        @store.has_key?(session_id)
      end

      def start_session
        raise MissingAuthorizationData unless authorization_data_present?

        private_session_key, private_session_key_seed = @authenticator.call(session_id, auth_data,
                                                                            auth_token)

        raise InvalidAuthorizationData unless private_session_key

        session_data = {
          'private_key' => private_session_key,
          'key_seed' => private_session_key_seed,
          'created_at' => Time.now.iso8601
        }

        @store.save_session_data(session_id, session_data, @session_id_ttl + @session_ttl)
      end

      def authenticate_session
        raise MissingAuthorizationData unless session_data_present?

        if session_expired? && authorization_data_present?
          start_session && return
        elsif session_expired?
          raise AuthorizationTimeout
        end
        session_data = @store.get_session_data(session_id)

        if authenticate_session_token(session_data['private_key'])
          raise InvalidAuthorizationData
        end
      end

      def authenticate_session_token(private_key)
        Digest::SHA1.hexdigest("#{private_key}\n#{auth_data}") != session_auth_token
      end

      def authorization_data_present?
        @env[DATE_HEADER] != nil && @env[AUTHENTICATION_HEADER] != nil &&
          extract_session_id(@env[AUTHENTICATION_HEADER]) != nil
      end

      def session_data_present?
        @env[DATE_HEADER] != nil && @env[BAAS_AUTHENTICATION_HEADER] != nil &&
          extract_session_id(@env[BAAS_AUTHENTICATION_HEADER]) != nil
      end

      def session_expired?
        session_data = @store.get_session_data(session_id)

        created_at = Time.iso8601(session_data['created_at'])

        (created_at + @session_ttl) < Time.now
      rescue Exception
        true
      end

      def auth_data
        "#{@env[DATE_HEADER]}\n" +
        "#{@env[REQUEST_HEADER]}\n" +
        "#{@env[PATH_HEADER]}"
      end

      def auth_token
        (@env[AUTHENTICATION_HEADER] || '').match(/.*:([a-zA-Z0-9]*)$/)
        $1
      end

      def session_id
        extract_session_id(@env[BAAS_AUTHENTICATION_HEADER]) ||
          extract_session_id(@env[AUTHENTICATION_HEADER])
      end

      def session_auth_token
        (@env[BAAS_AUTHENTICATION_HEADER] || '').match(/.*:([a-zA-Z0-9]*)$/)
        $1
      end

      def extract_session_id(data)
        (data || '').match(/^([a-zA-Z0-9]*):.*/)
        $1
      end

    end

  end
end