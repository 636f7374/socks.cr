class SOCKS::SessionProcessor
  property session : Session
  getter callback : Proc(Transfer, UInt64, UInt64, Nil)?
  getter heartbeatCallback : Proc(Transfer, Time::Span, Bool)?
  getter connectionReuse : Bool?

  def initialize(@session : Session, @callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
    @connectionReuse = nil
  end

  def perform(server : Server)
    return session.cleanup unless outbound = session.outbound

    transfer = Transfer.new source: session, destination: outbound, callback: callback, heartbeatCallback: heartbeat_proc
    set_transfer_options transfer: transfer
    session.set_transfer_tls transfer: transfer, reset: true

    perform transfer: transfer
    transfer.reset!

    loop do
      break unless session.options.switcher.allowConnectionReuse
      break unless check_support_connection_reuse?
      break if session.closed?
      break unless connectionReuse

      begin
        server.establish! session
      rescue ex
        session.cleanup rescue nil
        session.reset reset_tls: true

        break
      end

      unless outbound = session.outbound
        session.cleanup rescue nil
        session.reset reset_tls: true

        break
      end

      transfer.destination = outbound
      perform transfer: transfer
      transfer.reset!
    end
  end

  private def perform(transfer : Transfer)
    @connectionReuse = nil
    transfer.perform

    loop do
      break if check_inbound_connection_reuse transfer: transfer
      break if check_holding_connection_reuse transfer: transfer

      if transfer.done?
        transfer.cleanup
        session.reset reset_tls: true

        @connectionReuse = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  def perform(outbound : IO, connection_pool : ConnectionPool)
    transfer = Transfer.new source: session, destination: outbound, callback: callback, heartbeatCallback: heartbeat_proc
    session.set_transfer_tls transfer: transfer, reset: true

    perform transfer: transfer, connection_pool: connection_pool
  end

  def perform(transfer : Transfer, connection_pool : ConnectionPool)
    @connectionReuse = nil
    set_transfer_options transfer: transfer
    transfer.perform

    loop do
      break if check_outbound_connection_reuse transfer: transfer, connection_pool: connection_pool

      if transfer.done?
        transfer.cleanup
        session.reset reset_tls: true

        @connectionReuse = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  private def set_transfer_options(transfer : Transfer)
    # This function is used as an overridable.
    # E.g. SessionID.

    __set_transfer_options transfer: transfer
  end

  private def __set_transfer_options(transfer : Transfer)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval

    return unless transfer.destination.is_a? Layer::Server::UDPOutbound
    transfer.aliveInterval = session.options.session.udpAliveInterval
  end

  private def check_support_connection_reuse? : Bool
    session.inbound.is_a?(Enhanced::WebSocket) || session.holding.is_a?(Enhanced::WebSocket)
  end

  private def check_inbound_connection_reuse(transfer : Transfer) : Bool
    _session_inbound = session.inbound
    return false unless _session_inbound.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transfer.done?
      transfer.destination.close rescue nil unless transfer.destination.closed?

      _session_inbound.notify_peer_termination? command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE, closed_flag: SOCKS::Enhanced::ClosedFlag::DESTINATION rescue nil
      transfer.destination.close rescue nil unless transfer.destination.closed?

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      begin
        _session_inbound.response_pending_ping!
        _session_inbound.receive_peer_command_notify_decision! expect_command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE
      rescue ex
        _session_inbound.confirmed_connection_reuse = false
      end

      unless _session_inbound.confirmed_connection_reuse?
        transfer.cleanup
        session.reset reset_tls: true

        @connectionReuse = false
        _session_inbound.confirmed_connection_reuse = nil

        return true
      end

      transfer.cleanup side: Transfer::Side::Destination, free_tls: true, reset: true
      session.reset_peer side: Transfer::Side::Destination, reset_tls: true

      @connectionReuse = true
      _session_inbound.confirmed_connection_reuse = nil
      _session_inbound.pending_ping_command_bytes = nil

      return true
    end
  end

  private def check_holding_connection_reuse(transfer : Transfer) : Bool
    _session_holding = session.holding
    return false unless _session_holding.is_a? Enhanced::WebSocket

    loop do
      unless transfer.done?
        _session_holding.ping nil rescue nil
        sleep 0.25_f32.seconds

        next
      end

      _session_holding.notify_peer_termination! command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE, closed_flag: SOCKS::Enhanced::ClosedFlag::DESTINATION rescue nil
      transfer.destination.close rescue nil unless transfer.destination.closed?

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      begin
        _session_holding.response_pending_ping!
        _session_holding.receive_peer_command_notify_decision! expect_command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE
      rescue ex
        _session_holding.confirmed_connection_reuse = false
      end

      unless _session_holding.confirmed_connection_reuse?
        transfer.cleanup
        session.reset reset_tls: true

        @connectionReuse = false
        _session_holding.confirmed_connection_reuse = nil

        return true
      end

      transfer.cleanup side: Transfer::Side::Destination, free_tls: true, reset: true
      session.reset_peer side: Transfer::Side::Destination, reset_tls: true

      session.inbound.close rescue nil
      session.inbound = _session_holding
      session.holding = nil

      @connectionReuse = true
      _session_holding.confirmed_connection_reuse = nil
      _session_holding.pending_ping_command_bytes = nil

      return true
    end
  end

  private def check_outbound_connection_reuse(transfer : Transfer, connection_pool : ConnectionPool) : Bool
    transfer_destination = transfer.destination
    return false unless transfer_destination.is_a? Client
    enhanced_websocket = transfer_destination.outbound
    return false unless enhanced_websocket.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transfer.sent_done?

      transfer.source.close rescue nil unless transfer.source.closed?
      enhanced_websocket.notify_peer_termination? command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE, closed_flag: SOCKS::Enhanced::ClosedFlag::SOURCE rescue nil

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      begin
        enhanced_websocket.response_pending_ping!
        enhanced_websocket.receive_peer_command_notify_decision! expect_command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE
      rescue ex
        enhanced_websocket.confirmed_connection_reuse = false
      end

      unless enhanced_websocket.confirmed_connection_reuse?
        transfer.cleanup
        session.reset reset_tls: true

        @connectionReuse = false
        enhanced_websocket.confirmed_connection_reuse = nil

        return true
      end

      transfer.cleanup side: Transfer::Side::Source, free_tls: true, reset: true
      session.reset_peer side: Transfer::Side::Source, reset_tls: true
      transfer.reset!

      session.holding.try &.close rescue nil
      session.holding = nil
      transfer_destination.holding.try &.close rescue nil
      transfer_destination.holding = nil

      @connectionReuse = true
      enhanced_websocket.confirmed_connection_reuse = nil
      enhanced_websocket.pending_ping_command_bytes = nil
      connection_pool.unshift value: transfer

      return true
    end
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

          _session_outbound = session.outbound
          raise Exception.new unless _session_outbound.is_a? Client
          enhanced_websocket = _session_outbound.outbound
          raise Exception.new unless enhanced_websocket.is_a? Enhanced::WebSocket
          enhanced_websocket.ping nil
        rescue ex
          unless _heartbeat_callback
            sleep heartbeat_interval

            return false
          end
        end
      end

      unless _heartbeat_callback
        sleep heartbeat_interval

        return true
      end

      return !!heartbeat
    end
  end
end
