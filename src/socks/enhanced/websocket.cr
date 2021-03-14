require "http/web_socket"

module SOCKS::Enhanced
  class WebSocket < IO
    alias Opcode = HTTP::WebSocket::Protocol::Opcode
    alias Protocol = HTTP::WebSocket::Protocol

    enum PingFlag : UInt8
      KeepAlive = 0_u8
    end

    enum PongFlag : UInt8
      Confirmed = 0_u8
      Refused   = 1_u8
    end

    getter io : Protocol
    getter options : Options?
    getter windowRemaining : Atomic(Int32)
    getter buffer : IO::Memory
    getter ioMutex : Mutex
    getter mutex : Mutex

    def initialize(@io : Protocol, @options : Options? = nil)
      @windowRemaining = Atomic(Int32).new 0_i32
      @buffer = IO::Memory.new
      @ioMutex = Mutex.new :unchecked
      @mutex = Mutex.new :unchecked
    end

    def read_timeout=(value : Int | Time::Span | Nil)
      _io = io
      _io.read_timeout = value if value if _io.responds_to? :read_timeout=
    end

    def read_timeout
      _io = io
      _io.read_timeout if _io.responds_to? :read_timeout
    end

    def write_timeout=(value : Int | Time::Span | Nil)
      _io = io
      _io.write_timeout = value if value if _io.responds_to? :write_timeout=
    end

    def write_timeout
      _io = io
      _io.write_timeout if _io.responds_to? :write_timeout
    end

    def local_address : Socket::Address?
      _io = io
      _io.responds_to?(:local_address) ? _io.local_address : nil
    end

    def remote_address : Socket::Address?
      _io = io
      _io.responds_to?(:remote_address) ? _io.remote_address : nil
    end

    def keep_alive=(value : Bool?)
      @mutex.synchronize { @keepAlive = value }
    end

    def keep_alive?
      @mutex.synchronize { @keepAlive }
    end

    private def update_buffer
      receive_buffer = uninitialized UInt8[4096_i32]

      loop do
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .binary?
          self.windowRemaining.set receive.size

          buffer.rewind
          buffer.clear

          buffer.write receive_buffer.to_slice[0_i32, receive.size]
          buffer.rewind

          break
        when .ping?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next unless 1_i32 == slice.size

          ping_type = PingFlag.from_value slice.first rescue nil
          next pong nil unless _ping_type = ping_type

          case _ping_type
          in .keep_alive?
            process_enhanced_ping! ping_type: _ping_type
            raise Exception.new String.build { |io| io << "Received from IO to KeepAlive Ping permissionType (" << _ping_type << ")." }
          end
        when .pong?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next unless 1_i32 == slice.size

          pong_type = PongFlag.from_value slice.first rescue nil
          next unless _pong_type = pong_type

          case _pong_type
          in .confirmed?
            process_enhanced_pong! _pong_type
            raise Exception.new String.build { |io| io << "Received from IO to KeepAlive Pong permissionType (" << _pong_type << ")." }
          in .refused?
            process_enhanced_pong! _pong_type
            raise Exception.new String.build { |io| io << "Received from IO to KeepAlive Pong permissionType (" << _pong_type << ")." }
          end
        end
      end
    end

    def process_enhanced_ping!(ping_type : PingFlag? = nil)
      event = ping_type || receive_ping_event!

      case event
      in .keep_alive?
        allow_keep_alive = options.try &.switcher.try &.allowWebSocketKeepAlive

        if allow_keep_alive
          pong event: PongFlag::Confirmed

          self.keep_alive = true
        else
          pong event: PongFlag::Refused

          self.keep_alive = false
        end
      end
    end

    def process_enhanced_pong!(pong_type : PongFlag? = nil)
      event = pong_type || receive_pong_event!

      case event
      in .confirmed?
        allow_keep_alive = options.try &.switcher.try &.allowWebSocketKeepAlive

        if allow_keep_alive
          self.keep_alive = true
        else
          self.keep_alive = false
        end
      in .refused?
        self.keep_alive = false
      end
    end

    {% for name in ["ping", "pong"] %}
    def receive_{{name.id}}_event! : {{name.capitalize.id}}Flag
      receive_buffer = uninitialized UInt8[4096_i32]

      loop do
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .{{name.id}}?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next unless 1_i32 == slice.size

          enhanced_{{name.id}} = {{name.capitalize.id}}Flag.from_value slice.first rescue nil
          next unless enhanced_{{name.id}}

          break enhanced_{{name.id}}
        end
      end
    end
    {% end %}

    def pong(event : PongFlag? = nil)
      message = Bytes[event.to_i] if event

      @ioMutex.synchronize { io.pong message }
    end

    def ping(event : PingFlag? = nil)
      message = Bytes[event.to_i] if event

      @ioMutex.synchronize { io.ping message }
    end

    def read(slice : Bytes) : Int32
      return 0_i32 if slice.empty?
      update_buffer if windowRemaining.get.zero?

      length = buffer.read slice
      self.windowRemaining.add -length

      length
    end

    def write(slice : Bytes) : Nil
      @ioMutex.synchronize { io.send slice }
    end

    def flush
      io.flush
    end

    def close
      io.io_close
    end

    def closed?
      io.closed?
    end
  end
end
