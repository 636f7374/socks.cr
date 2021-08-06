module SOCKS::Enhanced
  class WebSocket < IO
    alias Opcode = HTTP::WebSocket::Protocol::Opcode
    alias Protocol = HTTP::WebSocket::Protocol

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

    def io : Protocol
      @io
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

    def confirmed_connection_reuse=(value : Bool?)
      @mutex.synchronize { @confirmedConnectionReuse = value }
    end

    def confirmed_connection_reuse?
      @mutex.synchronize { @confirmedConnectionReuse.dup }
    end

    def pending_ping_command_bytes=(value : Bytes?)
      @mutex.synchronize { @pendingPingCommandBytes = value }
    end

    def pending_ping_command_bytes
      @mutex.synchronize { @pendingPingCommandBytes.dup }
    end

    private def update_buffer
      receive_buffer = uninitialized UInt8[4096_i32]

      loop do
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .binary?
          self.windowRemaining.set receive.size

          @mutex.synchronize do
            buffer.rewind
            buffer.clear

            buffer.write receive_buffer.to_slice[0_i32, receive.size]
            buffer.rewind
          end

          break
        when .ping?
          slice = receive_buffer.to_slice[0_i32, receive.size].dup

          parse_ping_command?(slice: slice).try do |tuple|
            self.pending_ping_command_bytes = slice

            case tuple.first
            in .connection_reuse?
              raise Exception.new "Enhanced::WebSocket.update_buffer: Received Ping CommandFlag::CONNECTION_REUSE from io."
            end
          end
        when .pong?
          slice = receive_buffer.to_slice[0_i32, receive.size].dup

          parse_pong_command?(slice: slice).try do |tuple|
            case tuple.first
            in .connection_reuse?
              case tuple.last
              in .confirmed?
                self.confirmed_connection_reuse = true
                raise Exception.new "Enhanced::WebSocket.update_buffer: Received Pong CommandFlag::CONNECTION_REUSE (DecisionFlag::CONFIRMED) from io."
              in .refused?
                self.confirmed_connection_reuse = false
                raise Exception.new "Enhanced::WebSocket.update_buffer: Received Pong CommandFlag::CONNECTION_REUSE (DecisionFlag::REFUSED) from io."
              end
            end
          end
        end
      end
    end

    private def parse_ping_command?(slice : Bytes) : Tuple(CommandFlag, ClosedFlag)?
      return if slice.size < 2_i32

      command_flag = CommandFlag.from_value slice[0_i32] rescue nil
      return unless _command_flag = command_flag

      case _command_flag
      in .connection_reuse?
        closed_flag = ClosedFlag.from_value slice[1_i32] rescue nil
        return unless _closed_flag = closed_flag

        return Tuple.new command_flag, _closed_flag
      end
    end

    private def parse_pong_command?(slice : Bytes) : Tuple(CommandFlag, DecisionFlag)?
      return if slice.size < 2_i32

      command_flag = CommandFlag.from_value slice[0_i32] rescue nil
      return unless _command_flag = command_flag

      case _command_flag
      in .connection_reuse?
        decision_flag = DecisionFlag.from_value slice[1_i32] rescue nil
        return unless _decision_flag = decision_flag

        return Tuple.new command_flag, _decision_flag
      end
    end

    def notify_peer_termination?(command_flag : CommandFlag, closed_flag : ClosedFlag)
      notify_peer_termination! command_flag: command_flag, closed_flag: closed_flag
    end

    def notify_peer_termination!(command_flag : CommandFlag, closed_flag : ClosedFlag)
      ping Bytes[command_flag.value, closed_flag.value]
    end

    def response_pending_ping!
      return unless _pending_ping_command_bytes = pending_ping_command_bytes
      slice = _pending_ping_command_bytes

      parse_ping_command?(slice: slice).try do |tuple|
        case tuple.first
        in .connection_reuse?
          response_peer_termination! command_flag: tuple.first, decision_flag: nil
        end
      end
    end

    private def response_peer_termination!(command_flag : CommandFlag, decision_flag : DecisionFlag?)
      unless decision_flag
        decision_flag = options.try &.switcher.try &.allowConnectionReuse ? DecisionFlag::CONFIRMED : DecisionFlag::REFUSED
        decision_flag = DecisionFlag::REFUSED if false == confirmed_connection_reuse?
      end

      pong Bytes[command_flag.value, decision_flag.value]
    end

    def receive_peer_command_notify_decision!(expect_command_flag : CommandFlag) : DecisionFlag
      receive_buffer = uninitialized UInt8[4096_i32]

      finished_passive = false
      finished_passive = true if pending_ping_command_bytes
      finished_active = false
      finished_active = true if confirmed_connection_reuse?.is_a? Bool

      loop do
        break (confirmed_connection_reuse? ? DecisionFlag::CONFIRMED : DecisionFlag::REFUSED) if finished_passive && finished_active
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .ping?
          slice = receive_buffer.to_slice[0_i32, receive.size].dup

          parse_ping_command?(slice: slice).try do |tuple|
            finished_passive = true
            response_peer_termination! command_flag: tuple.first, decision_flag: nil
          end
        when .pong?
          slice = receive_buffer.to_slice[0_i32, receive.size].dup

          parse_pong_command?(slice: slice).try do |tuple|
            next unless tuple.first == expect_command_flag

            case tuple.first
            in .connection_reuse?
              finished_active = true
              self.confirmed_connection_reuse = tuple.last.confirmed? ? true : false
            end
          end
        end
      end
    end

    def ping(slice : Bytes?)
      @ioMutex.synchronize { io.ping slice }
    end

    def pong(slice : Bytes?)
      @ioMutex.synchronize { io.pong slice }
    end

    def read(slice : Bytes) : Int32
      return 0_i32 if slice.empty?
      update_buffer if windowRemaining.get.zero?

      length = @mutex.synchronize { buffer.read slice }
      self.windowRemaining.add -length

      length
    end

    def write(slice : Bytes) : Nil
      @ioMutex.synchronize { io.send slice }
    end

    def flush
      @ioMutex.synchronize { io.flush }
    end

    def close
      io.io_close
    end

    def closed?
      io.closed?
    end
  end
end

require "http/web_socket"
