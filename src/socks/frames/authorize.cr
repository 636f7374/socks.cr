struct SOCKS::Frames
  struct Authorize < Frames
    property authorizationType : WebSocketAuthorizationFlag
    property userName : String
    property password : String

    def initialize(@authorizationType : WebSocketAuthorizationFlag, @userName : String, @password : String)
    end
  end
end
