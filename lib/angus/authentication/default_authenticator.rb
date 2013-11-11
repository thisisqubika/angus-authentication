module Angus
  module Authentication
    class DefaultAuthenticator

      def initialize(private_key)
        @private_key = private_key
      end

      def call(session_id, auth_data, auth_token)
        if Digest::SHA1.hexdigest("#@private_key\n#{auth_data}") == auth_token
          private_session_key_seed = BCrypt::Engine.generate_salt
          private_session_key = Digest::SHA1.hexdigest(
            "#@private_key\n#{private_session_key_seed}"
          )

          return private_session_key, private_session_key_seed
        else
          return nil, nil
        end
      end

    end
  end
end