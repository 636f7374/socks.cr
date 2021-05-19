struct SOCKS::Options
  struct Server
    struct DestinationProtection
      property addresses : Set(Address)
      property ipAddresses : Set(Socket::IPAddress)
      property ipBlocks : Set(IPAddress::IPv4 | IPAddress::IPv6)

      def initialize
        @addresses = Set(Address).new
        @ipAddresses = Set(Socket::IPAddress).new
        @ipBlocks = Set(IPAddress::IPv4 | IPAddress::IPv6).new
      end
    end
  end
end
