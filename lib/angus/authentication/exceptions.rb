module Angus
  module Authentication

    class MissingAuthorizationData < StandardError

    end

    class InvalidAuthorizationData < StandardError

    end

    class AuthorizationTimeout < StandardError

    end

  end
end