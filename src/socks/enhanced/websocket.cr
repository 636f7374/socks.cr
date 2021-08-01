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
      @mutex.synchronize { @confirmedConnectionReuse }
    end

    def pending_ping_command_bytes=(value : Bytes)
      @mutex.synchronize { @pendingPingCommandBytes = value }
    end

    def pending_ping_command_bytes
      @mutex.synchronize { @pendingPingCommandBytes.dup }
    end

    def ignore_notify=(value : Bool)
      @mutex.synchronize { @ignoreNotify = value }
    end

    def ignore_notify?
      @mutex.synchronize { @ignoreNotify }
    end

    def process_pending_ping!
      return unless _pending_ping_command_bytes = pending_ping_command_bytes
      slice = _pending_ping_command_bytes

      command_flag = CommandFlag.from_value slice[0_i32] rescue nil
      return pong nil unless _command_flag = command_flag

      case _command_flag
      when CommandFlag::CONNECTION_REUSE
        closed_flag = ClosedFlag.from_value slice[1_i32] rescue nil
        return pong nil unless _closed_flag = closed_flag

        decision_flag = response_peer_termination! command_flag: _command_flag, decision_flag: nil
        self.confirmed_connection_reuse = true if decision_flag.confirmed?
      end
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
          next pong nil if slice.size < 2_i32

          command_flag = CommandFlag.from_value slice[0_i32] rescue nil
          next pong nil unless _command_flag = command_flag

          case _command_flag
          when CommandFlag::CONNECTION_REUSE
            closed_flag = ClosedFlag.from_value slice[1_i32] rescue nil
            next pong nil unless _closed_flag = closed_flag

            self.pending_ping_command_bytes = receive_buffer.to_slice[0_i32, receive.size].dup

            unless ignore_notify?
              raise Exception.new "Enhanced::WebSocket.update_buffer: Received Ping CommandFlag::CONNECTION_REUSE (DecisionFlag::CONFIRMED) from io."
            end
          end
        when .pong?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next if slice.size < 2_i32

          command_flag = CommandFlag.from_value slice[0_i32] rescue nil
          next unless _command_flag = command_flag

          case _command_flag
          when CommandFlag::CONNECTION_REUSE
            decision_flag = DecisionFlag.from_value slice[1_i32] rescue nil
            next unless _decision_flag = decision_flag

            case _decision_flag
            in .confirmed?
              self.confirmed_connection_reuse = true

              unless ignore_notify?
                raise Exception.new "Enhanced::WebSocket.update_buffer: Received Pong CommandFlag::CONNECTION_REUSE (DecisionFlag::CONFIRMED) from io."
              end
            in .refused?
              self.confirmed_connection_reuse = false
            end
          end
        end
      end
    end

    def notify_peer_termination!(command_flag : CommandFlag, closed_flag : ClosedFlag)
      raise Exception.new "Enhanced::WebSocket.notify_peer_termination!: Options.switcher.allowConnectionReuse is false." unless options.try &.switcher.try &.allowConnectionReuse
      raise Exception.new "Enhanced::WebSocket.notify_peer_termination!: Enhanced::WebSocket.confirmed_connection_reuse is false." if false === confirmed_connection_reuse?
      return if confirmed_connection_reuse?

      ping Bytes[command_flag.value, closed_flag.value]
    end

    private def response_peer_termination!(command_flag : CommandFlag, decision_flag : DecisionFlag?) : DecisionFlag
      unless decision_flag
        decision_flag = options.try &.switcher.try &.allowConnectionReuse ? DecisionFlag::CONFIRMED : DecisionFlag::REFUSED
        decision_flag = DecisionFlag::REFUSED if false == self.confirmed_connection_reuse?
      end

      pong Bytes[command_flag.value, decision_flag.value]

      decision_flag
    end

    protected def receive_peer_decision!(expect_command_flag : CommandFlag) : DecisionFlag
      receive_buffer = uninitialized UInt8[2_i32]

      loop do
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .pong?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next unless 2_i32 == slice.size

          received_command_flag = CommandFlag.from_value slice[0_i32] rescue nil
          received_decision_flag = DecisionFlag.from_value slice[1_i32] rescue nil
          next unless received_command_flag
          next unless received_decision_flag

          raise Exception.new String.build { |io| io << "Enhanced::WebSocket.receive_peer_decision!: ExpectCommandFlag (" << expect_command_flag << "), ReceivedCommandFlag (" << received_command_flag << ")." } unless expect_command_flag == received_command_flag

          break received_decision_flag
        end
      end
    end

    protected def receive_peer_command_notify_decision!(expect_command_flag : CommandFlag) : DecisionFlag
      receive_buffer = uninitialized UInt8[2_i32]

      loop do
        receive = io.receive receive_buffer.to_slice

        case receive.opcode
        when .ping?
          slice = receive_buffer.to_slice[0_i32, receive.size]
          next pong nil if slice.size < 2_i32

          received_command_flag = CommandFlag.from_value slice[0_i32] rescue nil
          next pong nil unless _received_command_flag = received_command_flag

          raise Exception.new String.build { |io| io << "Enhanced::WebSocket.receive_peer_command_notify_decision!: ExpectCommandFlag (" << expect_command_flag << "), ReceivedCommandFlag (" << received_command_flag << ")." } unless expect_command_flag == received_command_flag

          case _received_command_flag
          when CommandFlag::CONNECTION_REUSE
            closed_flag = ClosedFlag.from_value slice[1_i32] rescue nil
            next pong nil unless _closed_flag = closed_flag

            decision_flag = response_peer_termination! command_flag: _received_command_flag, decision_flag: nil

            if decision_flag.confirmed?
              self.confirmed_connection_reuse = true

              raise Exception.new "Enhanced::WebSocket.receive_peer_command_notify_decision!: Received Ping CommandFlag::CONNECTION_REUSE (DecisionFlag::CONFIRMED) from io."
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

      length = buffer.read slice
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
