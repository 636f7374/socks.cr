struct SOCKS::Options
  property session : Session
  property server : Server

  def initialize(@session : Session = Session.new, @server : Server = Server.new)
  end

  struct Session
    property udpAliveInterval : Time::Span
    property aliveInterval : Time::Span
    property heartbeatInterval : Time::Span

    def initialize
      @udpAliveInterval = 5_i32.seconds
      @aliveInterval = 30_i32.seconds
      @heartbeatInterval = 3_i32.seconds
    end
  end

  struct Server
    property allowWebSocketKeepAlive : Bool
    property allowTCPBinding : Bool
    property allowAssociateUDP : Bool
    property destinationProtection : DestinationProtection?

    def initialize
      @allowWebSocketKeepAlive = false
      @allowTCPBinding = true
      @allowAssociateUDP = true
      @destinationProtection = DestinationProtection.new
    end

    struct DestinationProtection
      property addresses : Set(Address)
      property ipAddresses : Set(Socket::IPAddress)

      def initialize
        @addresses = Set(Address).new
        @ipAddresses = Set(Socket::IPAddress).new
      end
    end
  end
end
