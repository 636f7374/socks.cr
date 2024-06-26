struct SOCKS::Options
  property connectionPool : ConnectionPool
  property switcher : Switcher
  property client : Client
  property server : Server
  property session : Session

  def initialize(@connectionPool : ConnectionPool = ConnectionPool.new, @switcher : Switcher = Switcher.new, @client : Client = Client.new, @server : Server = Server.new, @session : Session = Session.new)
  end

  struct ConnectionPool
    property clearInterval : Time::Span
    property capacity : Int32

    def initialize(@clearInterval : Time::Span = 10_i32.seconds, @capacity : Int32 = 5_i32)
    end
  end

  struct Switcher
    property allowConnectionReuse : Bool
    property enableConnectionIdentifier : Bool
    property allowTCPBinding : Bool
    property allowAssociateUDP : Bool

    def initialize
      @allowConnectionReuse = true
      @enableConnectionIdentifier = true
      @allowTCPBinding = true
      @allowAssociateUDP = true
    end
  end

  struct Client
    property wrapper : Wrapper?

    def initialize
      @wrapper = nil
    end

    abstract struct Wrapper
      struct WebSocket < Wrapper
        property address : Address
        property resource : String
        property headers : HTTP::Headers
        property dataRaw : String?

        def initialize(@address : Address, @resource : String, @headers : HTTP::Headers, @dataRaw : String?)
        end
      end
    end
  end

  struct Server
    property destinationBlocker : DestinationBlocker?
    property wrapper : Wrapper?

    def initialize
      @destinationBlocker = DestinationBlocker.new
      @wrapper = nil
    end

    struct DestinationBlocker
      property addresses : Set(Address)
      property ipAddresses : Set(Socket::IPAddress)

      def initialize
        @addresses = Set(Address).new
        @ipAddresses = Set(Socket::IPAddress).new
      end
    end

    abstract struct Wrapper
      struct WebSocket < Wrapper
      end
    end
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
end
