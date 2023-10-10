module SOCKS::SessionProcessor
  enum SideFlag : UInt8
    INBOUND  = 0_u8
    OUTBOUND = 2_u8
  end

  private def self.set_transfer_options(transfer : Transfer, session : Session, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    # This function is used as an overridable.
    # E.g. sessionId.

    __set_transfer_options transfer: transfer, session: session, exceed_threshold_flag: exceed_threshold_flag
  end

  private def self.__set_transfer_options(transfer : Transfer, session : Session, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval
    transfer.exceedThresholdFlag.set exceed_threshold_flag

    transfer_source = transfer.source
    transfer_destination = transfer.destination

    if transfer_source.is_a?(Enhanced::WebSocket) && transfer_source.allow_connection_pause?
      session.options.server.pausePool.try &.socketSwitchSeconds.try { |socket_switch_seconds| transfer.socketSwitchSeconds.set socket_switch_seconds.to_i.to_u64 }
      session.options.server.pausePool.try &.socketSwitchBytes.try { |socket_switch_bytes| transfer.socketSwitchBytes.set socket_switch_bytes }
      session.options.server.pausePool.try &.socketSwitchExpression.try { |socket_switch_expression| transfer.socketSwitchExpression.set socket_switch_expression }
    end

    case transfer_destination
    in Client
      transfer_destination_options = transfer_destination.options
      transfer_destination_outbound = transfer_destination.outbound

      if transfer_destination_outbound.is_a?(Enhanced::WebSocket) && transfer_destination_outbound.allow_connection_pause?
        transfer_destination_options_pause_pool = transfer_destination_options.client.pausePool

        if transfer_destination_options_pause_pool
          transfer.socketSwitchSeconds.set transfer_destination_options_pause_pool.socketSwitchSeconds.to_i.to_u64
          transfer.socketSwitchBytes.set transfer_destination_options_pause_pool.socketSwitchBytes
          transfer.socketSwitchExpression.set transfer_destination_options_pause_pool.socketSwitchExpression
        end
      end

      transfer.heartbeatInterval = transfer_destination_options.session.heartbeatInterval
      transfer.aliveInterval = transfer_destination_options.session.aliveInterval
    in Layer::AssociateUDP
      transfer.aliveInterval = session.options.session.udpAliveInterval
    in IO
    end
  end

  {% for name in ["inbound", "outbound"] %}
  def self.get_{{name.id}}_enhanced_websocket?(session : Session) : Enhanced::WebSocket?
    {% if name == "inbound" %}
      session_source = session.source
      return unless session_source.is_a? Enhanced::WebSocket
      
      session_source
    {% else %}
      session_destination = session.destination
      return unless session_destination.is_a? Client

      session_destination_outbound = session_destination.outbound
      return unless session_destination_outbound.is_a? Enhanced::WebSocket

      session_destination_outbound
    {% end %}
  end
  {% end %}

  def self.perform(server : Server, session : Session, pause_pool : PausePool? = nil, finish_callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Enhanced::CommandFlag?
    flag = perform session: session, pause_pool: pause_pool, finish_callback: finish_callback, heartbeat_callback: (heartbeat_callback ? heartbeat_proc(heartbeat_callback: heartbeat_callback) : heartbeat_proc(heartbeat_callback: nil))

    loop do
      case flag
      in Enhanced::CommandFlag
        case flag
        in .connection_reuse?
        in .connection_pause?
          break
        end
      in Nil
        session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }

        break
      end

      begin
        server.establish! session: session
      rescue ex
        session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }
        session.source.close rescue nil
        session.destination.try &.close rescue nil

        break
      end

      flag = perform session: session, pause_pool: pause_pool, finish_callback: finish_callback, heartbeat_callback: (heartbeat_callback ? heartbeat_proc(heartbeat_callback: heartbeat_callback) : heartbeat_proc(heartbeat_callback: nil))
    end
  end

  {% for name in ["inbound", "outbound"] %}
  {% if name == "inbound" %}
    def self.perform(session : Session, pause_pool : PausePool? = nil, finish_callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Enhanced::CommandFlag?
  {% else %}
    def self.perform(session : Session, reuse_pool : ReusePool? = nil, finish_callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Enhanced::CommandFlag?
  {% end %}

      unless session_destination = session.destination
        {% if name == "inbound" %}
          session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }
        {% end %}

        session.source.close rescue nil

        return
      end

      transfer = Transfer.new source: session.source, destination: session_destination, finishCallback: finish_callback, heartbeatCallback: (heartbeat_callback ? heartbeat_proc(heartbeat_callback: heartbeat_callback) : heartbeat_proc(heartbeat_callback: nil))

      {% if name == "inbound" %}
        exceed_threshold_flag = Transfer::ExceedThresholdFlag::RECEIVE
      {% else %}
        exceed_threshold_flag = Transfer::ExceedThresholdFlag::SENT
      {% end %}

      # Inbound: session.source
      # Outbound: session.destination.outbound

      set_transfer_options transfer: transfer, session: session, exceed_threshold_flag: exceed_threshold_flag
      enhanced_websocket = get_{{name.id}}_enhanced_websocket? session: session

      if enhanced_websocket
        {% if name == "inbound" %}
          enhanced_websocket.resynchronize rescue nil
          enhanced_websocket.transporting = true
        {% end %}
      end

      transfer.perform

      if enhanced_websocket
        {% if name == "inbound" %}
          value = check_process_inbound_connection enhanced_websocket: enhanced_websocket, transfer: transfer, pause_pool: pause_pool
        {% else %}
          value = check_process_outbound_connection enhanced_websocket: enhanced_websocket, transfer: transfer, reuse_pool: reuse_pool
        {% end %}

        case value
        in Enhanced::CommandFlag
          return value
        in Bool
          return
        end
      end

      loop do
        case transfer
        when .sent_done?
          transfer.destination.close rescue nil unless transfer.receive_done?

          break
        when .receive_done?
          transfer.source.close  rescue nil unless transfer.sent_done?

          break
        end

        sleep 0.01_f32.seconds
      end

      loop do
        next sleep 0.01_f32.seconds unless transfer.finished?

        break
      end

      transfer.source.close rescue nil
      transfer.destination.try &.close rescue nil

      nil
    end
  {% end %}

  private def self.check_process_inbound_connection(enhanced_websocket : Enhanced::WebSocket, transfer : Transfer, pause_pool : PausePool? = nil) : Enhanced::CommandFlag | Bool
    loop do
      next sleep 0.25_f32.seconds unless transfer.any_done?

      break
    end

    transfer_destination = transfer.destination
    transfer_destination.close_forwarder reset: false if transfer_destination.is_a? Client
    binding_connection = true if transfer_destination.is_a?(Layer::TCPBinding) || transfer_destination.is_a?(Layer::AssociateUDP)
    binding_connection = true if transfer_destination.tcp_forwarder || transfer_destination.udp_forwarder if transfer_destination.is_a? Client

    decision_command_flag = decision_notify_command_flag? transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: SideFlag::INBOUND, pause_pool: pause_pool, reuse_pool: nil
    decision_command_flag = nil if binding_connection && decision_command_flag.try &.connection_pause?
    connection_identifier = enhanced_websocket.connection_identifier
    _process_enhanced_finished = false

    if decision_command_flag
      enhanced_websocket.notify_peer_negotiate command_flag: decision_command_flag rescue nil

      case decision_command_flag
      in .connection_reuse?
        transfer.destination.close rescue nil
      in .connection_pause?
        if transfer.sent_done? && !transfer.receive_done? && enhanced_websocket.received_command?.nil?
          enhanced_command_flag = process_enhanced_finished source: transfer.destination, transfer: transfer, enhanced_websocket: enhanced_websocket
          _process_enhanced_finished = true

          transfer.source.close rescue nil
        end
      end
    else
      enhanced_websocket.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    transfer_destination.close_forwarder reset: true if transfer_destination.is_a? Client
    enhanced_command_flag = process_enhanced_finished source: transfer.destination, transfer: transfer, enhanced_websocket: enhanced_websocket unless _process_enhanced_finished
    enhanced_command_flag = nil if binding_connection && enhanced_command_flag.try &.connection_pause?

    case enhanced_command_flag
    in Enhanced::CommandFlag
      case enhanced_command_flag
      in .connection_reuse?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_REUSE
        transfer.destination.close rescue nil # keep source, dst set nil

        Enhanced::CommandFlag::CONNECTION_REUSE
      in .connection_pause?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_PAUSE
        transfer.source.close rescue nil # both set nil,

        if pause_pool && connection_identifier
          pause_pool.set connection_identifier: connection_identifier, destination: transfer.destination, state: enhanced_websocket.state

          Enhanced::CommandFlag::CONNECTION_PAUSE
        else
          transfer.destination.close rescue nil

          true
        end
      end
    in Nil
      enhanced_websocket.reset_settings command_flag: nil
      connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }

      transfer.source.close rescue nil
      transfer.destination.close rescue nil

      true
    end
  end

  private def self.check_process_outbound_connection(enhanced_websocket : Enhanced::WebSocket, transfer : Transfer, reuse_pool : ReusePool? = nil) : Enhanced::CommandFlag | Bool
    loop do
      next sleep 0.25_f32.seconds unless transfer.any_done?

      break
    end

    transfer_destination = transfer.destination
    transfer_destination.close_forwarder reset: false if transfer_destination.is_a? Client
    binding_connection = true if transfer_destination.is_a?(Layer::TCPBinding) || transfer_destination.is_a?(Layer::AssociateUDP)
    binding_connection = true if transfer_destination.tcp_forwarder || transfer_destination.udp_forwarder if transfer_destination.is_a? Client

    decision_command_flag = decision_notify_command_flag? transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: SideFlag::OUTBOUND, pause_pool: nil, reuse_pool: reuse_pool
    decision_command_flag = nil if binding_connection && decision_command_flag.try &.connection_pause?

    if decision_command_flag
      enhanced_websocket.notify_peer_negotiate command_flag: decision_command_flag rescue nil

      case decision_command_flag
      in .connection_reuse?
        transfer.source.close rescue nil
      in .connection_pause?
      end
    else
      enhanced_websocket.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    transfer_destination.close_forwarder reset: true if transfer_destination.is_a? Client
    enhanced_command_flag = process_enhanced_finished source: transfer.source, transfer: transfer, enhanced_websocket: enhanced_websocket
    enhanced_command_flag = nil if binding_connection && enhanced_command_flag.try &.connection_pause?
    connection_identifier = enhanced_websocket.connection_identifier

    case enhanced_command_flag
    in Enhanced::CommandFlag
      case enhanced_command_flag
      in .connection_reuse?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_REUSE
        transfer.source.close rescue nil

        unless transfer_destination.is_a? Client
          transfer.destination.close rescue nil

          return true
        end

        if reuse_pool
          reuse_pool.unshift value: enhanced_websocket, options: transfer_destination.options

          Enhanced::CommandFlag::CONNECTION_REUSE
        else
          transfer.destination.close rescue nil

          true
        end
      in .connection_pause?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_PAUSE
        transfer.destination.close rescue nil

        Enhanced::CommandFlag::CONNECTION_PAUSE
      end
    in Nil
      enhanced_websocket.reset_settings command_flag: nil

      transfer.source.close rescue nil
      transfer.destination.close rescue nil

      true
    end
  end

  private def self.decision_notify_command_flag?(transfer : Transfer, enhanced_websocket : Enhanced::WebSocket, side_flag : SideFlag, pause_pool : PausePool?, reuse_pool : ReusePool?) : Enhanced::CommandFlag?
    return if (!enhanced_websocket.allow_connection_reuse? && !enhanced_websocket.allow_connection_pause?) || !enhanced_websocket.connection_identifier
    _command_flag = enhanced_websocket.received_command_flag?

    unless _command_flag
      case side_flag
      in .inbound?
        _command_flag = enhanced_websocket.allow_connection_pause? ? Enhanced::CommandFlag::CONNECTION_PAUSE : Enhanced::CommandFlag::CONNECTION_REUSE
      in .outbound?
        _command_flag = enhanced_websocket.allow_connection_pause? ? Enhanced::CommandFlag::CONNECTION_PAUSE : Enhanced::CommandFlag::CONNECTION_REUSE unless _command_flag
      end
    end

    _command_flag = Enhanced::CommandFlag::CONNECTION_PAUSE unless _command_flag
    _command_flag = Enhanced::CommandFlag::CONNECTION_REUSE if transfer.sentBytes.get.zero? && transfer.receivedBytes.get.zero?
    _command_flag = Enhanced::CommandFlag::CONNECTION_REUSE if side_flag.inbound? && transfer.receive_exception?.try { |receive_exception| receive_exception.class == IO::TimeoutError }

    case _command_flag
    in .connection_reuse?
      return unless enhanced_websocket.allow_connection_reuse?
      return unless reuse_pool if side_flag.outbound?
    in .connection_pause?
      return unless enhanced_websocket.allow_connection_pause?
      return unless pause_pool if side_flag.inbound?
    end

    _command_flag
  end

  private def self.process_enhanced_finished(source : IO, transfer : Transfer, enhanced_websocket : Enhanced::WebSocket) : Enhanced::CommandFlag?
    return if (!enhanced_websocket.allow_connection_pause? && !enhanced_websocket.allow_connection_reuse?) || !enhanced_websocket.connection_identifier
    _exception = enhanced_websocket.process_negotiate source: source rescue nil

    unless negotiate_command_flag = enhanced_websocket.final_command_flag?
      negotiate_command_flag = Enhanced::CommandFlag::CONNECTION_PAUSE if enhanced_websocket.allow_connection_pause?
      negotiate_command_flag = Enhanced::CommandFlag::CONNECTION_REUSE if enhanced_websocket.allow_connection_reuse?
    end

    return unless negotiate_command_flag
    return if negotiate_command_flag.connection_reuse? && _exception
    return if negotiate_command_flag.connection_reuse? && !enhanced_websocket.allow_connection_reuse?
    return if negotiate_command_flag.connection_pause? && !enhanced_websocket.allow_connection_pause?

    if transfer.sentBytes.get.zero? && transfer.receivedBytes.get.zero? && negotiate_command_flag.try &.connection_pause?
      negotiate_command_flag = enhanced_websocket.allow_connection_reuse? ? Enhanced::CommandFlag::CONNECTION_REUSE : nil
    end

    negotiate_command_flag
  end

  private def self.heartbeat_proc(heartbeat_callback : Proc(Transfer, Time::Span, Bool)? = nil) : Proc(Transfer, Time::Span, Bool)?
    ->(transfer : Transfer, heartbeat_interval : Time::Span) do
      heartbeat = heartbeat_callback ? heartbeat_callback.call(transfer, heartbeat_interval) : true

      if heartbeat
        begin
          transfer_source = transfer.source
          transfer_source.ping slice: Bytes[Enhanced::StateFlag::HEARTBEAT] if transfer_source.is_a? Enhanced::WebSocket

          transfer_destination = transfer.destination
          raise Exception.new unless transfer_destination.is_a? Client
          transfer_destination_outbound = transfer_destination.outbound
          raise Exception.new unless transfer_destination_outbound.is_a? Enhanced::WebSocket
          transfer_destination_outbound.ping slice: Bytes[Enhanced::StateFlag::HEARTBEAT]
        rescue ex
          unless heartbeat_callback
            sleep heartbeat_interval

            return false
          end
        end
      end

      unless heartbeat_callback
        sleep heartbeat_interval

        return true
      end

      return !!heartbeat
    end
  end
end
