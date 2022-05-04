class SOCKS::SessionProcessor
  enum SideFlag : UInt8
    INBOUND  = 0_u8
    HOLDING  = 1_u8
    OUTBOUND = 2_u8
  end

  property session : Session
  getter finishCallback : Proc(Transfer, UInt64, UInt64, Nil)?
  getter heartbeatCallback : Proc(Transfer, Time::Span, Bool)?

  def initialize(@session : Session, @finishCallback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
  end

  private def set_transfer_options(transfer : Transfer, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    # This function is used as an overridable.
    # E.g. SessionID.

    __set_transfer_options transfer: transfer, exceed_threshold_flag: exceed_threshold_flag
  end

  private def __set_transfer_options(transfer : Transfer, exceed_threshold_flag : Transfer::ExceedThresholdFlag)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval
    transfer.finishCallback = finishCallback
    transfer.heartbeatCallback = heartbeatCallback ? heartbeatCallback : heartbeat_proc
    transfer.exceedThresholdFlag.set exceed_threshold_flag

    transfer_source = transfer.source
    transfer_destination = transfer.destination

    if transfer_source.is_a? Session
      session_inbound = transfer_source.inbound
      session_holding = transfer_source.holding

      enhanced_websocket = session_inbound if session_inbound.is_a? Enhanced::WebSocket
      enhanced_websocket = session_holding if session_holding.is_a? Enhanced::WebSocket unless enhanced_websocket

      if enhanced_websocket.is_a?(Enhanced::WebSocket) && enhanced_websocket.allow_connection_pause?
        session.options.server.pausePool.try &.socketSwitchSeconds.try { |socket_switch_seconds| transfer.socketSwitchSeconds.set socket_switch_seconds.to_i.to_u64 }
        session.options.server.pausePool.try &.socketSwitchBytes.try { |socket_switch_bytes| transfer.socketSwitchBytes.set socket_switch_bytes }
        session.options.server.pausePool.try &.socketSwitchExpression.try { |socket_switch_expression| transfer.socketSwitchExpression.set socket_switch_expression }
      end
    end

    if transfer_destination.is_a? Client
      transfer_destination_options = transfer_destination.options
      transfer_destination_outbound = transfer_destination.outbound

      if transfer_destination_outbound.is_a?(Enhanced::WebSocket) && transfer_destination_outbound.allow_connection_pause?
        transfer_destination_options.client.pausePool.try &.socketSwitchSeconds.try { |socket_switch_seconds| transfer.socketSwitchSeconds.set socket_switch_seconds.to_i.to_u64 }
        transfer_destination_options.client.pausePool.try &.socketSwitchBytes.try { |socket_switch_bytes| transfer.socketSwitchBytes.set socket_switch_bytes }
        transfer_destination_options.client.pausePool.try &.socketSwitchExpression.try { |socket_switch_expression| transfer.socketSwitchExpression.set socket_switch_expression }
      end

      transfer.heartbeatInterval = transfer_destination_options.session.heartbeatInterval
      transfer.aliveInterval = transfer_destination_options.session.aliveInterval
    end

    if transfer_destination.is_a? Layer::Server::UDPOutbound
      transfer.aliveInterval = session.options.session.udpAliveInterval
    end
  end

  {% for name in ["inbound", "outbound"] %}
  def get_{{name.id}}_enhanced_websocket?(session : Session) : Tuple(SideFlag, Enhanced::WebSocket)?
    {% if name == "inbound" %}
      session_inbound = session.inbound
      return Tuple.new SideFlag::INBOUND, session_inbound if session_inbound.is_a? Enhanced::WebSocket
    {% else %}
      session_outbound_client = session.outbound
      return unless session_outbound_client.is_a? Client

      session_outbound = session_outbound_client.outbound
      return Tuple.new SideFlag::OUTBOUND, session_outbound if session_outbound.is_a? Enhanced::WebSocket
    {% end %}
  end
  {% end %}

  def perform(server : Server, pause_pool : PausePool? = nil) : Enhanced::CommandFlag?
    unless session_outbound = session.outbound
      session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }
      session.syncCloseOutbound = true
      session.cleanup

      return
    end

    transfer = Transfer.new source: session.inbound, destination: session_outbound, finishCallback: nil, heartbeatCallback: nil
    flag = perform transfer: transfer, pause_pool: pause_pool

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
        server.establish! session
      rescue ex
        session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }
        session.syncCloseOutbound = true
        session.cleanup

        break
      end

      unless session_outbound = session.outbound
        session.connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }
        session.syncCloseOutbound = true
        session.cleanup

        break
      end

      transfer = Transfer.new source: session.inbound, destination: session_outbound, finishCallback: nil, heartbeatCallback: nil
      flag = perform transfer: transfer, pause_pool: pause_pool

      next
    end
  end

  {% for name in ["inbound", "outbound"] %}
  {% if name == "inbound" %}
    def perform(transfer : Transfer, pause_pool : PausePool? = nil) : Enhanced::CommandFlag?
  {% else %}
    def perform(transfer : Transfer, reuse_pool : ReusePool? = nil) : Enhanced::CommandFlag?
  {% end %}
      session.syncCloseOutbound = false

      {% if name == "inbound" %}
        exceed_threshold_flag = Transfer::ExceedThresholdFlag::RECEIVE
      {% else %}
        exceed_threshold_flag = Transfer::ExceedThresholdFlag::SENT
      {% end %}

      set_transfer_options transfer: transfer, exceed_threshold_flag: exceed_threshold_flag
      tuple = get_{{name.id}}_enhanced_websocket? session: session

      tuple.try do |_tuple|
        side_flag, enhanced_websocket = _tuple

        {% if name == "inbound" %}
          enhanced_websocket.resynchronize rescue nil
          enhanced_websocket.transporting = true
        {% end %}
      end

      transfer.perform

      if tuple
        {% if name == "inbound" %}
          value = check_process_inbound_connection enhanced_websocket: tuple.last, side_flag: tuple.first, transfer: transfer, pause_pool: pause_pool
        {% else %}
          value = check_process_outbound_connection enhanced_websocket: tuple.last, transfer: transfer, reuse_pool: reuse_pool
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
          transfer.destination.close rescue nil unless transfer.destination.closed?

          break
        when .receive_done?
          transfer.source.close rescue nil unless transfer.source.closed?

          break
        end

        sleep 0.01_f32.seconds
      end

      loop do
        next sleep 0.01_f32.seconds unless transfer.finished?

        break
      end

      session.syncCloseOutbound = true
      session.cleanup

      nil
    end
  {% end %}

  private def check_process_inbound_connection(enhanced_websocket : Enhanced::WebSocket, side_flag : SideFlag, transfer : Transfer, pause_pool : PausePool? = nil) : Enhanced::CommandFlag | Bool
    loop do
      break if transfer.any_done?
      next sleep 0.25_f32.seconds unless side_flag.holding?

      begin
        enhanced_websocket.ping nil
        enhanced_websocket.synchronize synchronize_flag: Enhanced::State::SynchronizeFlag::NEGOTIATE
      rescue ex
        break
      end
    end

    decision_command_flag = decision_notify_command_flag? transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: side_flag, pause_pool: pause_pool, reuse_pool: nil
    connection_identifier = enhanced_websocket.connection_identifier
    _process_enhanced_finished = false

    if decision_command_flag
      enhanced_websocket.notify_peer_negotiate command_flag: decision_command_flag rescue nil

      case decision_command_flag
      in .connection_reuse?
        transfer.destination.close rescue nil
      in .connection_pause?
        if transfer.sent_done? && !transfer.receive_done? && enhanced_websocket.received_command?.nil?
          enhanced_command_flag = process_enhanced_finished source: transfer.destination, transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: side_flag
          _process_enhanced_finished = true

          transfer.source.close rescue nil
        end
      end
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    unless _process_enhanced_finished
      enhanced_command_flag = process_enhanced_finished source: transfer.destination, transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: side_flag
    end

    case enhanced_command_flag
    in Enhanced::CommandFlag
      case enhanced_command_flag
      in .connection_reuse?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_REUSE
        transfer.reset_settings! reset_socket_switch_seconds: false, reset_socket_switch_bytes: false, reset_socket_switch_expression: false

        case side_flag
        in .holding?
          session.inbound.try &.close rescue nil
          session.inbound = enhanced_websocket
        in .inbound?
          session.holding.try &.close rescue nil
        in .outbound?
        end

        session.holding = nil
        session.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true

        Enhanced::CommandFlag::CONNECTION_REUSE
      in .connection_pause?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_PAUSE
        transfer.reset_settings! reset_socket_switch_seconds: false, reset_socket_switch_bytes: false, reset_socket_switch_expression: false

        session.holding.try &.close rescue nil
        session.holding = nil
        session.cleanup sd_flag: Transfer::SDFlag::SOURCE, reset: true

        transfer.reset_socket sd_flag: Transfer::SDFlag::SOURCE
        connection_identifier.try { |_connection_identifier| pause_pool.try &.set connection_identifier: _connection_identifier, value: transfer, state: enhanced_websocket.state }

        Enhanced::CommandFlag::CONNECTION_PAUSE
      end
    in Nil
      enhanced_websocket.reset_settings command_flag: nil
      transfer.reset_settings! reset_socket_switch_seconds: false, reset_socket_switch_bytes: false, reset_socket_switch_expression: false
      connection_identifier.try { |_connection_identifier| pause_pool.try &.remove_connection_identifier connection_identifier: _connection_identifier }

      session.syncCloseOutbound = true
      session.cleanup

      true
    end
  end

  private def check_process_outbound_connection(enhanced_websocket : Enhanced::WebSocket, transfer : Transfer, reuse_pool : ReusePool? = nil) : Enhanced::CommandFlag | Bool
    loop do
      next sleep 0.25_f32.seconds unless transfer.any_done?

      break
    end

    decision_command_flag = decision_notify_command_flag? transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: SideFlag::OUTBOUND, pause_pool: nil, reuse_pool: reuse_pool

    if decision_command_flag
      enhanced_websocket.notify_peer_negotiate command_flag: decision_command_flag rescue nil

      case decision_command_flag
      in .connection_reuse?
        transfer.source.close rescue nil
      in .connection_pause?
      end
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      break
    end

    enhanced_command_flag = process_enhanced_finished source: transfer.source, transfer: transfer, enhanced_websocket: enhanced_websocket, side_flag: SideFlag::OUTBOUND
    connection_identifier = enhanced_websocket.connection_identifier

    case enhanced_command_flag
    in Enhanced::CommandFlag
      case enhanced_command_flag
      in .connection_reuse?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_REUSE
        transfer.reset_settings! reset_socket_switch_seconds: false, reset_socket_switch_bytes: false, reset_socket_switch_expression: false

        session.holding.try &.close rescue nil
        session.holding = nil
        session.cleanup sd_flag: Transfer::SDFlag::SOURCE, reset: true

        transfer.reset_socket sd_flag: Transfer::SDFlag::SOURCE
        reuse_pool.try { |_reuse_pool| _reuse_pool.unshift value: transfer }

        Enhanced::CommandFlag::CONNECTION_REUSE
      in .connection_pause?
        enhanced_websocket.reset_settings command_flag: Enhanced::CommandFlag::CONNECTION_PAUSE
        transfer.reset_socket

        session.holding.try &.close rescue nil
        session.holding = nil
        session.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true

        Enhanced::CommandFlag::CONNECTION_PAUSE
      end
    in Nil
      enhanced_websocket.reset_settings command_flag: nil
      transfer.reset_socket

      session.syncCloseOutbound = true
      session.cleanup

      true
    end
  end

  private def decision_notify_command_flag?(transfer : Transfer, enhanced_websocket : Enhanced::WebSocket, side_flag : SideFlag, pause_pool : PausePool?, reuse_pool : ReusePool?) : Enhanced::CommandFlag?
    return if (!enhanced_websocket.allow_connection_reuse? && !enhanced_websocket.allow_connection_pause?) || !enhanced_websocket.connection_identifier
    _command_flag = enhanced_websocket.received_command_flag?

    unless _command_flag
      case side_flag
      in .inbound?
        _command_flag = enhanced_websocket.allow_connection_pause? ? Enhanced::CommandFlag::CONNECTION_PAUSE : Enhanced::CommandFlag::CONNECTION_REUSE
      in .holding?
        _command_flag = Enhanced::CommandFlag::CONNECTION_REUSE
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
      return if side_flag.holding?
      return unless pause_pool if side_flag.inbound?
    end

    _command_flag
  end

  private def process_enhanced_finished(source : IO, transfer : Transfer, enhanced_websocket : Enhanced::WebSocket, side_flag : SideFlag) : Enhanced::CommandFlag?
    _exception = enhanced_websocket.process_negotiate source: source rescue nil

    _command_flag = enhanced_websocket.final_command_flag?
    _command_flag = Enhanced::CommandFlag::CONNECTION_PAUSE if enhanced_websocket.allow_connection_pause? unless _command_flag
    _command_flag = Enhanced::CommandFlag::CONNECTION_REUSE if enhanced_websocket.allow_connection_reuse? unless _command_flag
    return unless _command_flag

    return if _command_flag.connection_reuse? && _exception
    return if _command_flag.connection_reuse? && !enhanced_websocket.allow_connection_reuse?
    return if _command_flag.connection_pause? && !enhanced_websocket.allow_connection_pause?

    if side_flag.holding? && _command_flag.connection_pause?
      _command_flag = enhanced_websocket.allow_connection_reuse? ? Enhanced::CommandFlag::CONNECTION_REUSE : nil
    end

    if transfer.sentBytes.get.zero? && transfer.receivedBytes.get.zero? && _command_flag.try &.connection_pause?
      _command_flag = enhanced_websocket.allow_connection_reuse? ? Enhanced::CommandFlag::CONNECTION_REUSE : nil
    end

    _command_flag
  end

  private def heartbeat_proc : Proc(Transfer, Time::Span, Bool)?
    ->(transfer : Transfer, heartbeat_interval : Time::Span) do
      _heartbeat_callback = heartbeatCallback
      heartbeat = _heartbeat_callback ? _heartbeat_callback.call(transfer, heartbeat_interval) : true

      if heartbeat
        begin
          _session_inbound = session.inbound
          _session_inbound.ping nil if _session_inbound.is_a? Enhanced::WebSocket

          _session_holding = session.holding
          _session_holding.ping nil if _session_holding.is_a? Enhanced::WebSocket

          session_outbound_client = session.outbound
          raise Exception.new unless session_outbound_client.is_a? Client
          session_outbound = session_outbound_client.outbound
          raise Exception.new unless session_outbound.is_a? Enhanced::WebSocket
          session_outbound.ping nil
        rescue ex
          unless _heartbeat_callback
            transfer.reset_monitor_state
            sleep heartbeat_interval

            return false
          end
        end
      end

      unless _heartbeat_callback
        transfer.reset_monitor_state
        sleep heartbeat_interval

        return true
      end

      return !!heartbeat
    end
  end
end
