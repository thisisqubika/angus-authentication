require 'angus/authentication/provider'

module Rack
  module Middleware

    class AngusAuthentication

      UNAUTHORIZED_MESSAGE = 'Unauthorized'
      TIMEOUT_MESSAGE = 'Authentication Timeout'

      def initialize(app, settings = {})
        @app = app

        @authentication_settings = settings
      end

      def call(env)
        authentication_provider = Angus::Authentication::Provider.new(@authentication_settings, env)

        authentication_provider.authenticate!

        response = @app.call(env)

        authentication_provider.update_response_header(response)

        response
      rescue Angus::Authentication::MissingAuthorizationData,
             Angus::Authentication::InvalidAuthorizationData
        [401, {}, [UNAUTHORIZED_MESSAGE]]
      rescue Angus::Authentication::AuthorizationTimeout
        [419, {}, [TIMEOUT_MESSAGE]]
      end

    end

  end
end