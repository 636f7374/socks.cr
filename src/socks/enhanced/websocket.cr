module SOCKS::Enhanced
  class WebSocket < IO
    getter io : HTTP::WebSocket::Protocol
    getter options : Options?
    property state : State::WebSocket

    def initialize(@io : HTTP::WebSocket::Protocol, @options : Options? = nil, @state : State::WebSocket = State::WebSocket.new)
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

    protected def maximum_sent_sequence=(value : Int8) : Int8
      state.maximum_sent_sequence = value
    end

    protected def maximum_receive_sequence=(value : Int8) : Int8
      state.maximum_receive_sequence = value
    end

    protected def allow_connection_reuse=(value : Bool?)
      state.allow_connection_reuse = value
    end

    def allow_connection_reuse? : Bool
      state.allow_connection_reuse?
    end

    protected def allow_connection_pause=(value : Bool?)
      state.allow_connection_pause = value
    end

    def allow_connection_pause? : Bool
      state.allow_connection_pause?
    end

    protected def connection_identifier=(value : UUID?)
      state.connection_identifier = value
    end

    def connection_identifier
      state.connection_identifier
    end

    {% for name in ["synchronizing", "transporting"] %}
    def {{name.id}}=(value : Bool)
      state.{{name.id}} = value
    end

    def {{name.id}}? : Bool
      state.{{name.id}}
    end
    {% end %}

    {% for name in ["send", "received"] %}
    def {{name.id}}_command? : Tuple(Int64, CommandFlag)?
      state.{{name.id}}_command?
    end

    def {{name.id}}_command_flag? : CommandFlag?
      state.{{name.id}}_command_flag?
    end
    {% end %}

    def reset_settings(command_flag : CommandFlag?) : Bool
      state.reset_settings command_flag: command_flag
    end

    def process_response_pending_command_negotiate
      state.process_response_pending_command_negotiate io: io
    end

    def process_client_side_connection_pause_pending! : State::QueueFlag
      state.process_client_side_connection_pause_pending! io: io
    end

    def process_server_side_connection_pause_pending!(connection_identifier : UUID, pause_pool : PausePool) : PausePool::Entry?
      state.process_server_side_connection_pause_pending! io: io, connection_identifier: connection_identifier, pause_pool: pause_pool
    end

    def notify_peer_negotiate(command_flag : CommandFlag)
      state.notify_peer_negotiate io: io, command_flag: command_flag
    end

    def notify_peer_incoming
      state.notify_peer_incoming io: io
    end

    def process_negotiate(source : IO)
      state.process_negotiate io: io, source: source
    end

    def resynchronize
      state.resynchronize io: io
    end

    def synchronize(synchronize_flag : State::SynchronizeFlag, ignore_incoming_alert : Bool = true)
      state.synchronize io: io, synchronize_flag: synchronize_flag, ignore_incoming_alert: ignore_incoming_alert
    end

    def ping(slice : Bytes?)
      state.ping io: io, slice: slice
    end

    def pong(slice : Bytes?)
      state.pong io: io, slice: slice
    end

    def read(slice : Bytes) : Int32
      state.read io: io, slice: slice
    end

    def write(slice : Bytes) : Nil
      state.write io: io, slice: slice
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

    {% for name in ["send", "received"] %}
    def {{name.id}}_command? : Tuple(Int64, CommandFlag)?
      state.{{name.id}}_command?
    end

    def {{name.id}}_command_flag? : CommandFlag?
      state.{{name.id}}_command_flag?
    end
    {% end %}

    def final_command_flag? : CommandFlag?
      state.final_command_flag?
    end
  end
end
