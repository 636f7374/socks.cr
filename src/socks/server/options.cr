class SOCKS::Server
  struct Options
    property allowWebSocketKeepAlive : Bool
    property allowTCPBinding : Bool
    property allowAssociateUDP : Bool
    property syncCreateOutboundSocket : Bool
    property destinationProtection : DestinationProtection?

    def initialize
      @allowWebSocketKeepAlive = false
      @allowTCPBinding = true
      @allowAssociateUDP = true
      @syncCreateOutboundSocket = true
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
