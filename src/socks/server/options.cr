class SOCKS::Server
  struct Options
    property allowWebSocketKeepAlive : Bool
    property allowTCPBinding : Bool
    property allowAssociateUDP : Bool
    property syncCreateOutboundSocket : Bool

    def initialize
      @allowWebSocketKeepAlive = false
      @allowTCPBinding = true
      @allowAssociateUDP = true
      @syncCreateOutboundSocket = true
    end
  end
end
