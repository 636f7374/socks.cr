struct SOCKS::Options
  property switcher : Switcher
  property client : Client
  property server : Server
  property session : Session

  def initialize(@switcher : Switcher = Switcher.new, @client : Client = Client.new, @server : Server = Server.new, @session : Session = Session.new)
  end

  struct Switcher
    property enableConnectionIdentifier : Bool
    property allowConnectionPause : Bool
    property allowConnectionReuse : Bool
    property allowTCPBinding : Bool
    property allowAssociateUDP : Bool

    def initialize(@enableConnectionIdentifier : Bool = true, @allowConnectionPause : Bool = true, @allowConnectionReuse : Bool = true, @allowTCPBinding : Bool = true, @allowAssociateUDP : Bool = true)
    end
  end

  struct Client
    property reusePool : ReusePool
    property pausePool : PausePool
    property wrapper : Wrapper?

    def initialize(@reusePool : ReusePool = ReusePool.new, @pausePool : PausePool = PausePool.new, @wrapper : Wrapper? = nil)
    end

    struct ReusePool
      property clearInterval : Time::Span
      property capacity : Int32

      def initialize(@clearInterval : Time::Span = 10_i32.seconds, @capacity : Int32 = 5_i32)
      end
    end

    struct PausePool
      property socketSwitchSeconds : Time::Span
      property socketSwitchBytes : UInt64
      property socketSwitchExpression : Transfer::SocketSwitchExpressionFlag

      def initialize(@socketSwitchSeconds : Time::Span = 720_i32.seconds, @socketSwitchBytes : UInt64 = 100000000_u64, @socketSwitchExpression : Transfer::SocketSwitchExpressionFlag = Transfer::SocketSwitchExpressionFlag::OR)
      end
    end

    abstract struct Wrapper
      struct WebSocket < Wrapper
        property address : Address
        property resource : String
        property headers : HTTP::Headers
        property dataRaw : String?
        property maximumSentSequence : Int8
        property maximumReceiveSequence : Int8

        def initialize(@address : Address, @resource : String, @headers : HTTP::Headers, @dataRaw : String?, @maximumSentSequence : Int8 = Int8::MAX, @maximumReceiveSequence : Int8 = Int8::MAX)
        end
      end
    end
  end

  struct Server
    property pausePool : PausePool
    property destinationBlocker : DestinationBlocker?
    property wrapper : Wrapper?

    def initialize(@pausePool : PausePool = PausePool.new, @destinationBlocker : DestinationBlocker = DestinationBlocker.new, @wrapper : Wrapper? = nil)
    end

    struct PausePool
      property clearInterval : Time::Span
      property capacity : Int32
      property socketSwitchSeconds : Time::Span
      property socketSwitchBytes : UInt64
      property socketSwitchExpression : Transfer::SocketSwitchExpressionFlag

      def initialize(@clearInterval : Time::Span = 60_i32.seconds, @capacity : Int32 = 128_i32, @socketSwitchSeconds : Time::Span = 720_i32.seconds, @socketSwitchBytes : UInt64 = 100000000_u64, @socketSwitchExpression : Transfer::SocketSwitchExpressionFlag = Transfer::SocketSwitchExpressionFlag::OR)
      end
    end

    struct DestinationBlocker
      property addresses : Set(Address)
      property ipAddresses : Set(Socket::IPAddress)

      def initialize(@addresses : Set(Address) = Set(Address).new, @ipAddresses : Set(Socket::IPAddress) = Set(Socket::IPAddress).new)
      end
    end

    abstract struct Wrapper
      struct WebSocket < Wrapper
        property maximumSentSequence : Int8
        property maximumReceiveSequence : Int8

        def initialize(@maximumSentSequence : Int8 = Int8::MAX, @maximumReceiveSequence : Int8 = Int8::MAX)
        end
      end
    end
  end

  struct Session
    property udpAliveInterval : Time::Span
    property aliveInterval : Time::Span
    property heartbeatInterval : Time::Span

    def initialize(@udpAliveInterval : Time::Span = 5_i32.seconds, @aliveInterval : Time::Span = 30_i32.seconds, @heartbeatInterval : Time::Span = 3_i32.seconds)
    end
  end
end
