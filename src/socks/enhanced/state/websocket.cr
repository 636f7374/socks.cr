module SOCKS::Enhanced
  abstract class State
    class WebSocket < State
      getter allowConnectionReuse : Atomic(Int8)
      getter allowConnectionPause : Atomic(Int8)
      getter maximumSentSequence : Atomic(Int8)
      getter maximumReceiveSequence : Atomic(Int8)
      getter sentSequence : Atomic(Int8)
      getter receiveSequence : Atomic(Int8)
      getter sentRound : Atomic(UInt64)
      getter receiveRound : Atomic(UInt64)
      getter sentBufferSet : Set(Bytes)
      getter receiveBuffer : IO::Memory
      getter receiveRescueBuffer : IO::Memory
      getter synchronizing : Atomic(Int8)
      getter reading : Atomic(Int8)
      getter writing : Atomic(Int8)
      getter receivedCommand : Tuple(Int64, CommandFlag)?
      getter sendCommand : Tuple(Int64, CommandFlag)?
      getter sendActiveAskCommand : Atomic(Int8)
      getter receivedSendReplyCommand : Atomic(Int8)
      getter receivedPassiveAskCommand : Atomic(Int8)
      getter replyPassiveAskCommand : Atomic(Int8)
      getter transporting : Atomic(Int8)
      getter anyDone : Atomic(Int8)
      getter sentMutex : Mutex
      getter receiveMutex : Mutex
      getter synchronizeMutex : Mutex
      getter mutex : Mutex

      def initialize
        @allowConnectionReuse = Atomic(Int8).new -1_i8
        @allowConnectionPause = Atomic(Int8).new -1_i8
        @maximumSentSequence = Atomic(Int8).new 127_i8
        @maximumReceiveSequence = Atomic(Int8).new 127_i8
        @sentSequence = Atomic(Int8).new -1_i8
        @receiveSequence = Atomic(Int8).new -1_i8
        @sentRound = Atomic(UInt64).new 0_u64
        @receiveRound = Atomic(UInt64).new 0_u64
        @sentBufferSet = Set(Bytes).new
        @receiveBuffer = IO::Memory.new
        @receiveRescueBuffer = IO::Memory.new
        @synchronizing = Atomic(Int8).new -1_i8
        @reading = Atomic(Int8).new -1_i8
        @writing = Atomic(Int8).new -1_i8
        @receivedCommand = nil
        @sendCommand = nil
        @sendActiveAskCommand = Atomic(Int8).new -1_i8
        @receivedSendReplyCommand = Atomic(Int8).new -1_i8
        @receivedPassiveAskCommand = Atomic(Int8).new -1_i8
        @replyPassiveAskCommand = Atomic(Int8).new -1_i8
        @transporting = Atomic(Int8).new -1_i8
        @anyDone = Atomic(Int8).new -1_i8
        @sentMutex = Mutex.new :unchecked
        @receiveMutex = Mutex.new :unchecked
        @synchronizeMutex = Mutex.new :unchecked
        @mutex = Mutex.new :unchecked
      end

      protected def maximum_sent_sequence=(value : Int8)
        @maximumSentSequence.set value
      end

      def maximum_sent_sequence : Int8
        _maximum_sent_sequence = @maximumSentSequence.get
        _maximum_sent_sequence <= 0_i8 ? Int8::MAX : _maximum_sent_sequence
      end

      protected def maximum_receive_sequence=(value : Int8)
        @maximumReceiveSequence.set value
      end

      def maximum_receive_sequence : Int8
        _maximum_receive_sequence = @maximumReceiveSequence.get
        _maximum_receive_sequence <= 0_i8 ? Int8::MAX : _maximum_receive_sequence
      end

      protected def allow_connection_reuse=(value : Bool?)
        return if !value && (-1_i8 == allowConnectionReuse.get)
        return if value && allowConnectionReuse.get.zero?

        @allowConnectionReuse.set(value ? 0_i8 : -1_i8)
      end

      def allow_connection_reuse? : Bool
        @allowConnectionReuse.get.zero?
      end

      protected def allow_connection_pause=(value : Bool?)
        return if !value && (-1_i8 == allowConnectionPause.get)
        return if value && allowConnectionPause.get.zero?

        @allowConnectionPause.set(value ? 0_i8 : -1_i8)
      end

      def allow_connection_pause? : Bool
        @allowConnectionPause.get.zero?
      end

      def receive_buffer_end_of_reached? : Bool
        @receiveMutex.synchronize { (receiveBuffer.pos == receiveBuffer.size) || receiveBuffer.size.zero? }
      end

      def receive_end_of_reached? : Bool
        receiveSequence.get == maximum_receive_sequence
      end

      {% for name in ["sent", "receive"] %}
      def maximum_{{name.id}}_sequence=(value : Int8)
        @maximum{{name.capitalize.id}}Sequence.set value
      end

      def {{name.id}}_sequence_reset
        @{{name.id}}Sequence.set -1_i8
      end
      {% end %}

      {% for name in ["send", "received"] %}
      def {{name.id}}_command=(value : Tuple(Int64, CommandFlag))
        @mutex.synchronize { @{{name.id}}Command = value }
      end

      def {{name.id}}_command? : Tuple(Int64, CommandFlag)?
        @mutex.synchronize { @{{name.id}}Command.dup }
      end

      def {{name.id}}_command_flag? : CommandFlag?
        {{name.id}}_command?.try &.last
      end
      {% end %}

      def send_active_ask_command=(value : Bool)
        return if !value && (-1_i8 == sendActiveAskCommand.get)
        return if value && sendActiveAskCommand.get.zero?

        @sendActiveAskCommand.set(value ? 0_i8 : -1_i8)
      end

      def send_active_ask_command? : Bool
        @sendActiveAskCommand.get.zero?
      end

      def received_send_reply_command=(value : Bool)
        return if !value && (-1_i8 == receivedSendReplyCommand.get)
        return if value && receivedSendReplyCommand.get.zero?

        @receivedSendReplyCommand.set(value ? 0_i8 : -1_i8)
      end

      def received_send_reply_command? : Bool
        @receivedSendReplyCommand.get.zero?
      end

      def received_passive_ask_command=(value : Bool)
        return if !value && (-1_i8 == receivedPassiveAskCommand.get)
        return if value && receivedPassiveAskCommand.get.zero?

        @receivedPassiveAskCommand.set(value ? 0_i8 : -1_i8)
      end

      def received_passive_ask_command? : Bool
        @receivedPassiveAskCommand.get.zero?
      end

      def reply_passive_ask_command=(value : Bool)
        return if !value && (-1_i8 == replyPassiveAskCommand.get)
        return if value && replyPassiveAskCommand.get.zero?

        @replyPassiveAskCommand.set(value ? 0_i8 : -1_i8)
      end

      def reply_passive_ask_command? : Bool
        @replyPassiveAskCommand.get.zero?
      end

      def any_done=(value : Bool)
        return if !value && (-1_i8 == anyDone.get)
        return if value && anyDone.get.zero?

        @anyDone.set(value ? 0_i8 : -1_i8)
      end

      def any_done? : Bool
        @anyDone.get.zero?
      end

      def connection_identifier=(value : UUID?)
        @mutex.synchronize { @connectionIdentifier ||= value }
      end

      def connection_identifier
        @mutex.synchronize { @connectionIdentifier }
      end

      {% for name in ["synchronizing", "transporting", "reading", "writing"] %}
      def {{name.id}}=(value : Bool)
        return if !value && (-1_i8 == {{name.id}}.get)
        return if value && {{name.id}}.get.zero?

        @{{name.id}}.set(value ? 0_i8 : -1_i8)
      end

      def {{name.id}}? : Bool
        @{{name.id}}.get.zero?
      end
      {% end %}

      protected def reset_settings(command_flag : CommandFlag?) : Bool
        @mutex.synchronize do
          if !command_flag || command_flag.try &.connection_reuse?
            @sentSequence.set -1_i8
            @receiveSequence.set -1_i8
            @sentRound.set 0_u64
            @receiveRound.set 0_u64
            @sentBufferSet.clear
            @receiveBuffer.clear
            @receiveRescueBuffer.clear
          end

          @synchronizing.set -1_i8
          @reading.set -1_i8
          @writing.set -1_i8
          @receivedCommand = nil
          @sendCommand = nil
          @sendActiveAskCommand.set -1_i8
          @receivedSendReplyCommand.set -1_i8
          @receivedPassiveAskCommand.set -1_i8
          @replyPassiveAskCommand.set -1_i8
          @transporting.set -1_i8
          @anyDone.set -1_i8
        end

        true
      end

      def final_command_flag? : CommandFlag?
        received_command = received_command?
        send_command = send_command?
        return if received_command.nil? && send_command.nil?

        _command_flag = send_command.last if received_command.nil? && send_command.is_a?(Tuple(Int64, CommandFlag))
        _command_flag = received_command.last if send_command.nil? && received_command.is_a?(Tuple(Int64, CommandFlag))

        if received_command.is_a?(Tuple(Int64, CommandFlag)) && send_command.is_a?(Tuple(Int64, CommandFlag))
          _command_flag = received_command.first < send_command.first ? received_command.last : send_command.last
        end

        _command_flag
      end

      {% for name in ["state", "command", "queue"] %}
      protected def parse_{{name.id}}_flag?(memory_slice : IO::Memory) : {{name.capitalize.id}}Flag?
        return if memory_slice.empty?

        {{name.id}}_flag_value = memory_slice.read_bytes UInt8, IO::ByteFormat::BigEndian
        {{name.capitalize.id}}Flag.from_value {{name.id}}_flag_value rescue nil
      end
      {% end %}

      protected def parse_unix_ms?(memory_slice : IO::Memory) : Int64?
        return if memory_slice.empty?
        memory_slice.read_bytes Int64, IO::ByteFormat::BigEndian rescue nil
      end

      protected def parse_resynchronize_frame(memory_slice : IO::Memory) : Tuple(Int8, Int8, UInt64)
        peer_sent_sequence = memory_slice.read_bytes Int8, IO::ByteFormat::BigEndian
        peer_receive_sequence = memory_slice.read_bytes Int8, IO::ByteFormat::BigEndian
        peer_receive_round = memory_slice.read_bytes UInt64, IO::ByteFormat::BigEndian

        Tuple.new peer_sent_sequence, peer_receive_sequence, peer_receive_round
      end

      protected def parse_sent_frame(memory_slice : IO::Memory) : Tuple(Int8, Int32)
        sent_sequence = memory_slice.read_bytes Int8, IO::ByteFormat::BigEndian
        size = memory_slice.read_bytes Int32, IO::ByteFormat::BigEndian

        Tuple.new sent_sequence, size
      end

      protected def create_sent_frame(slice : Bytes, sent_sequence : Int8) : Bytes
        temporary = IO::Memory.new
        temporary.write_bytes StateFlag::SENT.value, IO::ByteFormat::BigEndian
        temporary.write_bytes sent_sequence, IO::ByteFormat::BigEndian
        temporary.write_bytes slice.size, IO::ByteFormat::BigEndian
        temporary.write slice
        temporary.to_slice
      end

      private def create_resynchronize_frame(sent_sequence : Int8, receive_sequence : Int8, receive_round : UInt64) : Bytes
        temporary = IO::Memory.new capacity: 11_i32
        temporary.write_bytes StateFlag::RESYNCHRONIZE.value, IO::ByteFormat::BigEndian
        temporary.write_bytes sent_sequence, IO::ByteFormat::BigEndian
        temporary.write_bytes receive_sequence, IO::ByteFormat::BigEndian
        temporary.write_bytes receive_round, IO::ByteFormat::BigEndian
        temporary.to_slice
      end

      {% for name in ["received_confirmed"] %}
      private def create_{{name.id}}_frame(receive_sequence : Int8) : Bytes
        temporary = IO::Memory.new capacity: 2_i32
        temporary.write_bytes StateFlag::{{name.upcase.id}}.value, IO::ByteFormat::BigEndian
        temporary.write_bytes receive_sequence, IO::ByteFormat::BigEndian
        temporary.to_slice
      end
      {% end %}

      {% for name in ["notify_peer", "response_peer"] %}
      protected def {{name.id}}_command_negotiate(io : HTTP::WebSocket::Protocol, command_flag : CommandFlag) : Int64
        unix_ms = Time.local.to_unix_ms

        memory_slice = IO::Memory.new capacity: 10_i32
        memory_slice.write_bytes StateFlag::COMMAND.value, IO::ByteFormat::BigEndian
        memory_slice.write_bytes command_flag.value, IO::ByteFormat::BigEndian
        memory_slice.write_bytes unix_ms, IO::ByteFormat::BigEndian

        {% if name == "notify_peer" %}
          ping io: io, slice: memory_slice.to_slice
        {% else %}
          pong io: io, slice: memory_slice.to_slice
        {% end %}

        unix_ms
      end
      {% end %}

      protected def notify_peer_receive_end_of_reached(io : HTTP::WebSocket::Protocol)
        ping io: io, slice: create_received_confirmed_frame(receive_sequence: receiveSequence.get)
      end

      def notify_peer_incoming(io : HTTP::WebSocket::Protocol)
        ping io: io, slice: Bytes[StateFlag::INCOMING.value]
      end

      def process_response_pending_command_negotiate(io : HTTP::WebSocket::Protocol)
        return if reply_passive_ask_command?
        return unless _received_command_flag = received_command_flag?

        response_peer_command_negotiate io: io, command_flag: _received_command_flag
        self.reply_passive_ask_command = true
      end

      protected def notify_peer_negotiate(io : HTTP::WebSocket::Protocol, command_flag : CommandFlag)
        return if send_active_ask_command?

        unix_ms = notify_peer_command_negotiate io: io, command_flag: command_flag
        self.send_active_ask_command = true
        self.send_command = Tuple.new unix_ms, command_flag
      end

      protected def process_receive_end_of_reached(io : HTTP::WebSocket::Protocol)
        notify_peer_receive_end_of_reached io: io
        receive_sequence_reset
        receiveRound.add 1_u64
      end

      def process_negotiate(io : HTTP::WebSocket::Protocol, source : IO) : Exception?
        _exception = nil

        io_read_timeout = io.read_timeout.dup
        io_write_timeout = io.write_timeout.dup
        io.read_timeout = 5_i32.seconds
        io.write_timeout = 5_i32.seconds
        process_response_pending_command_negotiate io: io rescue nil

        loop do
          @receiveMutex.synchronize { IO.copy src: receiveBuffer, dst: source rescue nil }
          break if send_active_ask_command? && received_send_reply_command? && received_passive_ask_command? && reply_passive_ask_command?

          begin
            synchronize io: io, synchronize_flag: SynchronizeFlag::NEGOTIATE, ignore_incoming_alert: false
          rescue ex : Transfer::TerminateConnection
            next
          rescue ex
            @receiveMutex.synchronize { IO.copy src: receiveBuffer, dst: source rescue nil }
            _exception = ex

            break
          end
        end

        io.read_timeout = io_read_timeout
        io.write_timeout = io_write_timeout
        self.transporting = false

        _exception
      end

      def process_client_side_connection_pause_pending!(io : HTTP::WebSocket::Protocol) : QueueFlag
        ping io: io, slice: nil
        receive_buffer = uninitialized UInt8[64_i32]

        loop do
          receive = @receiveMutex.synchronize { io.receive receive_buffer.to_slice }

          case receive.opcode
          when .pong?
            memory_slice = IO::Memory.new receive_buffer.to_slice[0_i32, receive.size].dup
            raise Exception.new "Enhanced::State::WebSocket.process_client_side_connection_pause_pending: QueueFlag.from_value is Nil!" unless queue_flag = parse_queue_flag? memory_slice: memory_slice

            case queue_flag
            in .waiting?
              ping io: io, slice: nil
              sleep 0.25_f32.seconds
            in .ready?
              break queue_flag
            in .refused?
              break queue_flag
            end
          end
        end
      end

      def process_server_side_connection_pause_pending!(io : HTTP::WebSocket::Protocol, connection_identifier : UUID, pause_pool : PausePool) : PausePool::Entry?
        receive_buffer = uninitialized UInt8[64_i32]

        loop do
          receive = @receiveMutex.synchronize { io.receive receive_buffer.to_slice }

          case receive.opcode
          when .ping?
            unless pause_pool.connection_identifier_includes? connection_identifier: connection_identifier
              pong io: io, slice: Bytes[QueueFlag::REFUSED.value]

              break
            end

            case entry = pause_pool.get? connection_identifier: connection_identifier
            in PausePool::Entry
              pong io: io, slice: Bytes[QueueFlag::READY.value]

              break entry
            in Nil
              pong io: io, slice: Bytes[QueueFlag::WAITING.value]
            end
          end
        end
      end

      {% for name in ["readable", "writeable"] %}
      private def wait_{{name.id}}!(io : HTTP::WebSocket::Protocol)
        loop do
          {% if name == "readable" %}
            break unless receive_buffer_end_of_reached?
          {% else %}
            break unless sentSequence.get == maximum_sent_sequence
          {% end %}

          rb_flag = synchronize io: io, synchronize_flag: SynchronizeFlag::{{name.upcase.id}}, ignore_incoming_alert: true

          case rb_flag
          in .ready?
            break
          in .busy?
            sleep 0.001_f32.seconds
          in .none?
          end
        end
      end
      {% end %}

      def resynchronize(io : HTTP::WebSocket::Protocol)
        resynchronize_frame = create_resynchronize_frame sent_sequence: sentSequence.get, receive_sequence: receiveSequence.get, receive_round: receiveRound.get
        ping io: io, slice: resynchronize_frame

        synchronize io: io, synchronize_flag: SynchronizeFlag::RESYNCHRONIZE, ignore_incoming_alert: true
      end

      def synchronize(io : HTTP::WebSocket::Protocol, synchronize_flag : SynchronizeFlag, ignore_incoming_alert : Bool = true) : RBFlag
        begin
          loop do
            ready = synchronize_ready? synchronize_flag: synchronize_flag
            return ready if ready
            break unless synchronizing?

            return RBFlag::BUSY
          end

          __synchronize io: io, synchronize_flag: synchronize_flag
        rescue ex : IncomingAlert
          self.synchronizing = false
          raise ex unless ignore_incoming_alert

          RBFlag::NONE
        rescue ex
          self.synchronizing = false

          raise ex
        end
      end

      protected def __synchronize(io : HTTP::WebSocket::Protocol, synchronize_flag : SynchronizeFlag) : RBFlag
        @synchronizeMutex.synchronize do
          ready = synchronize_ready? synchronize_flag: synchronize_flag

          if ready
            self.synchronizing = false
            return ready
          end

          self.synchronizing = true
          receive_buffer = uninitialized UInt8[4102_i32]

          loop do
            receive = @receiveMutex.synchronize { io.receive receive_buffer.to_slice }

            if synchronize_flag.resynchronize? && receive.opcode.binary?
              raise Exception.new "Enhanced::State::WebSocket.synchronize: synchronizeFlag is RESYNCHRONIZE, Binary Opcode is received! (Unexpected)."
            end

            case receive.opcode
            when .binary?
              break if synchronize_flag.negotiate?
              memory_slice = IO::Memory.new receive_buffer.to_slice[0_i32, receive.size]

              if allow_connection_pause?
                break unless state_flag = parse_state_flag? memory_slice: memory_slice
                break unless state_flag.sent?

                receiveSequence.add 1_i8 if transporting?
                peer_sent_sequence, size = parse_sent_frame memory_slice: memory_slice
                receive_sequence = receiveSequence.get

                if transporting? && (peer_sent_sequence != receive_sequence)
                  receiveSequence.add -1_i8
                  raise Exception.new "Enhanced::State::WebSocket.synchronize: peerSentSequence does not match receiveSequence!"
                end
              end

              @receiveMutex.synchronize do
                if receiveBuffer.pos == receiveBuffer.size
                  receiveBuffer.rewind
                  receiveBuffer.clear
                end

                receive_buffer_pos = receiveBuffer.pos.dup
                receiveBuffer.pos = receiveBuffer.size
                IO.copy memory_slice, receiveBuffer
                receiveBuffer.pos = receive_buffer_pos
              end

              process_receive_end_of_reached io: io if allow_connection_pause? && receive_end_of_reached?
            when .ping?
              memory_slice = IO::Memory.new receive_buffer.to_slice[0_i32, receive.size]
              state_flag = parse_state_flag? memory_slice: memory_slice
              break pong io: io, slice: nil if state_flag.nil?

              if synchronize_flag.resynchronize? && !state_flag.resynchronize?
                raise Exception.new "Enhanced::State::WebSocket.synchronize: synchronizeFlag is RESYNCHRONIZE, but the received Ping StateFlag is not RESYNCHRONIZE."
              end

              case state_flag
              in .sent?
                raise Exception.new "Enhanced::State::WebSocket.synchronize: Ping StateFlag is SENT, Unexpected Error."
              in .received_confirmed?
                sentRound.add 1_u64
                @mutex.synchronize { sentBufferSet.clear }
                sent_sequence_reset
              in .resynchronize?
                peer_sent_sequence, peer_receive_sequence, peer_receive_round = parse_resynchronize_frame memory_slice: memory_slice
                received_confirmed = ((peer_receive_round - 1_u64) == sentRound.get) && (sentSequence.get == maximum_sent_sequence) && (peer_receive_sequence == -1_i8) rescue false

                if received_confirmed
                  sentRound.add 1_u64
                  @mutex.synchronize { sentBufferSet.clear }
                  sent_sequence_reset
                else
                  raise Exception.new "Enhanced::State::WebSocket.synchronize: peerReceiveSequence does not match sentSequence!" if peer_receive_sequence > sentSequence.get

                  @mutex.synchronize do
                    sentBufferSet.each_with_index do |slice, index|
                      next if index <= peer_receive_sequence
                      @sentMutex.synchronize { io.send data: slice }
                    end
                  end
                end
              in .command?
                break unless transporting?
                break unless command_flag = parse_command_flag? memory_slice: memory_slice
                break unless unix_ms = parse_unix_ms? memory_slice: memory_slice

                self.received_command = Tuple.new unix_ms, command_flag
                process_response_pending_command_negotiate io: io if synchronize_flag.negotiate?

                case command_flag
                in .connection_reuse?
                  self.received_passive_ask_command = true
                  self.any_done = true

                  raise Transfer::TerminateConnection.new "Enhanced::State::WebSocket.synchronize: Received Ping CommandFlag::CONNECTION_REUSE from io."
                in .connection_pause?
                  self.received_passive_ask_command = true
                  self.any_done = true

                  raise Transfer::TerminateConnection.new "Enhanced::State::WebSocket.synchronize: Received Ping CommandFlag::CONNECTION_PAUSE from io."
                end
              in .incoming?
                pong io: io, slice: Bytes[StateFlag::INCOMING.value]
                raise State::IncomingAlert.new
              end
            when .pong?
              memory_slice = IO::Memory.new receive_buffer.to_slice[0_i32, receive.size]
              state_flag = parse_state_flag? memory_slice: memory_slice
              break if state_flag.nil?

              case state_flag
              in .sent?
              in .received_confirmed?
              in .resynchronize?
              in .command?
                break unless transporting?
                break unless command_flag = parse_command_flag? memory_slice: memory_slice

                case command_flag
                in .connection_reuse?
                  self.received_send_reply_command = true
                  self.any_done = true

                  raise Transfer::TerminateConnection.new "Enhanced::State::WebSocket.synchronize: Received Pong CommandFlag::CONNECTION_REUSE from io."
                in .connection_pause?
                  self.received_send_reply_command = true
                  self.any_done = true

                  raise Transfer::TerminateConnection.new "Enhanced::State::WebSocket.synchronize: Received Pong CommandFlag::CONNECTION_PAUSE from io."
                end
              in .incoming?
                raise State::IncomingAlert.new
              end
            end

            break
          end

          self.synchronizing = false
          RBFlag::NONE
        end
      end

      protected def synchronize_ready?(synchronize_flag : SynchronizeFlag) : RBFlag?
        case synchronize_flag
        in .readable?
          return RBFlag::READY unless @receiveMutex.synchronize { receiveBuffer.pos == receiveBuffer.size }
        in .writeable?
          return RBFlag::READY unless transporting?
          return RBFlag::READY unless sentSequence.get == maximum_sent_sequence
        in .resynchronize?
        in .negotiate?
        end
      end

      def update_receive_rescue_buffer(slice : Bytes) : Bool
        @receiveMutex.synchronize { @receiveRescueBuffer.clear } if @receiveMutex.synchronize { @receiveRescueBuffer.pos == @receiveRescueBuffer.size }
        @receiveMutex.synchronize { @receiveRescueBuffer.write slice }

        true
      end

      def ping(io : HTTP::WebSocket::Protocol, slice : Bytes?)
        @sentMutex.synchronize { io.ping message: slice }
      end

      def pong(io : HTTP::WebSocket::Protocol, slice : Bytes?)
        @sentMutex.synchronize { io.pong message: slice }
      end

      def read(io : HTTP::WebSocket::Protocol, slice : Bytes) : Int32
        raise Transfer::TerminateConnection.new "Enhanced::State::WebSocket.read: TerminateConnection received!" if self.any_done?
        return 0_i32 if slice.empty?

        if transporting? && receiveMutex.synchronize { @receiveRescueBuffer.pos != @receiveRescueBuffer.size }
          length = @receiveMutex.synchronize { @receiveRescueBuffer.read slice }
          @receiveMutex.synchronize { @receiveRescueBuffer.clear } if @receiveMutex.synchronize { @receiveRescueBuffer.pos == @receiveRescueBuffer.size }

          return length
        end

        loop do
          unless reading?
            self.reading = true

            break
          end

          sleep 0.01_f32.seconds
        end

        begin
          wait_readable! io: io
        rescue ex
          self.reading = false

          raise ex
        end

        length = @receiveMutex.synchronize { receiveBuffer.read slice }
        self.reading = false
        length
      end

      def write(io : HTTP::WebSocket::Protocol, slice : Bytes) : Nil
        loop do
          unless writing?
            self.writing = true

            break
          end

          sleep 0.01_f32.seconds
        end

        begin
          wait_writeable! io: io
        rescue ex
          self.writing = false

          raise ex
        end

        if transporting? && allow_connection_pause?
          sentSequence.add 1_i8
          sent_sequence = sentSequence.get
        else
          sent_sequence = -1_i8
        end

        sent_frame = allow_connection_pause? ? create_sent_frame(slice: slice, sent_sequence: sent_sequence) : slice
        @mutex.synchronize { @sentBufferSet << sent_frame } if transporting? && allow_connection_pause?

        begin
          @sentMutex.synchronize { io.send data: sent_frame }
        rescue ex
          exception = ex
        end

        unless exception
          begin
            wait_writeable! io: io
          rescue ex
            exception = ex
          end
        end

        self.writing = false
        raise Transfer::TerminateConnection.new message: "Enhanced::State::WebSocket.write: TerminateConnection received!", cause: exception if self.any_done?
        exception.try { |_exception| raise _exception }
      end
    end
  end
end
