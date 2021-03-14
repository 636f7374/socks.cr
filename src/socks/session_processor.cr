class SOCKS::SessionProcessor
  property session : Session

  def initialize(@session : Session)
  end

  private def keep_alive=(value : Bool?)
    @keepAlive = value
  end

  private def keep_alive?
    @keepAlive
  end

  def perform(server : Server)
    return session.cleanup unless outbound = session.outbound

    transfer = Transfer.new source: session, destination: outbound, heartbeat: heartbeat_proc
    set_transfer_options transfer: transfer
    session.set_transfer_tls transfer: transfer
    perform transfer: transfer
    transfer.reset!

    loop do
      break unless session.options.server.allowWebSocketKeepAlive
      break unless check_support_keep_alive?
      break if session.closed?
      break unless keep_alive?

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
    self.keep_alive = nil
    transfer.perform

    loop do
      break if check_inbound_keep_alive transfer: transfer
      break if check_holding_keep_alive transfer: transfer

      if transfer.done?
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  def perform(outbound : IO, connection_pool : ConnectionPool)
    transfer = Transfer.new source: session, destination: outbound, heartbeat: heartbeat_proc
    session.set_transfer_tls transfer: transfer
    perform transfer: transfer, connection_pool: connection_pool
  end

  def perform(transfer : Transfer, connection_pool : ConnectionPool)
    set_transfer_options transfer: transfer
    self.keep_alive = nil
    transfer.perform

    loop do
      break if check_outbound_keep_alive transfer: transfer, connection_pool: connection_pool

      if transfer.done?
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  private def set_transfer_options(transfer : Transfer)
    transfer.heartbeatInterval = session.options.session.heartbeatInterval
    transfer.aliveInterval = session.options.session.aliveInterval

    return unless transfer.destination.is_a? Quirks::Server::UDPOutbound
    transfer.aliveInterval = session.options.session.udpAliveInterval
  end

  private def check_support_keep_alive? : Bool
    session.inbound.is_a?(Enhanced::WebSocket) || session.holding.is_a?(Enhanced::WebSocket)
  end

  private def check_inbound_keep_alive(transfer : Transfer) : Bool
    _session_inbound = session.inbound
    return false unless _session_inbound.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transfer.done?
      transfer.destination.close rescue nil

      loop do
        next sleep 0.25_f32.seconds unless transfer.finished?

        unless _session_inbound.keep_alive?
          transfer.cleanup
          session.reset reset_tls: true

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        begin
          _session_inbound.ping Enhanced::WebSocket::PingFlag::KeepAlive
          received = _session_inbound.receive_pong_event!
          raise Exception.new String.build { |io| io << "SessionProcessor.check_inbound_keep_alive: Received from IO to failure status (" << received << ")." } unless received.confirmed?
        rescue ex
          transfer.cleanup
          session.reset reset_tls: true

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        transfer.cleanup side: Transfer::Side::Destination, free_tls: true, reset: true
        session.reset_peer side: Transfer::Side::Destination, reset_tls: true

        self.keep_alive = true
        _session_inbound.keep_alive = nil

        return true
      end
    end
  end

  private def check_holding_keep_alive(transfer : Transfer) : Bool
    _session_holding = session.holding
    return false unless _session_holding.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transfer.done?

      transfer.destination.close rescue nil
      _session_holding.process_enhanced_ping! rescue nil

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      unless _session_holding.keep_alive?
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      begin
        _session_holding.ping Enhanced::WebSocket::PingFlag::KeepAlive
        received = _session_holding.receive_pong_event!
        raise Exception.new String.build { |io| io << "SessionProcessor.check_holding_keep_alive: Received from IO to failure status (" << received << ")." } unless received.confirmed?
      rescue ex
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      transfer.cleanup side: Transfer::Side::Destination, free_tls: true, reset: true
      session.reset_peer side: Transfer::Side::Destination, reset_tls: true

      session.inbound.close rescue nil
      session.inbound = _session_holding
      session.holding = nil

      self.keep_alive = true
      _session_holding.keep_alive = nil

      return true
    end
  end

  private def check_outbound_keep_alive(transfer : Transfer, connection_pool : ConnectionPool) : Bool
    transfer_destination = transfer.destination
    return false unless transfer_destination.is_a? Client
    enhanced_websocket = transfer_destination.outbound
    return false unless enhanced_websocket.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transfer.sent_done?
      enhanced_websocket.ping SOCKS::Enhanced::WebSocket::PingFlag::KeepAlive rescue nil

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transfer.finished?

      unless enhanced_websocket.keep_alive?
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        enhanced_websocket.keep_alive = nil

        return true
      end

      begin
        received = enhanced_websocket.receive_ping_event!
        raise Exception.new String.build { |io| io << "SessionProcessor.check_outbound_keep_alive: Received from IO to failure status (" << received << ")." } unless received.keep_alive?
        enhanced_websocket.pong event: SOCKS::Enhanced::WebSocket::PongFlag::Confirmed
      rescue ex
        transfer.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        enhanced_websocket.keep_alive = nil

        return true
      end

      transfer.cleanup side: Transfer::Side::Source, free_tls: true, reset: true
      session.reset_peer side: Transfer::Side::Source, reset_tls: true
      transfer.reset!

      session.holding.try &.close rescue nil
      session.holding = nil
      transfer_destination.holding.try &.close rescue nil
      transfer_destination.holding = nil

      self.keep_alive = true
      enhanced_websocket.keep_alive = nil
      connection_pool.unshift value: transfer

      return true
    end
  end

  private def heartbeat_proc : Proc(Nil)?
    ->do
      _session_inbound = session.inbound
      _session_inbound.ping rescue nil if _session_inbound.is_a? Enhanced::WebSocket

      _session_holding = session.holding
      _session_holding.ping rescue nil if _session_holding.is_a? Enhanced::WebSocket

      _session_outbound = session.outbound
      return unless _session_outbound.is_a? Client
      enhanced_websocket = _session_outbound.outbound
      return unless enhanced_websocket.is_a? Enhanced::WebSocket
      enhanced_websocket.ping rescue nil
    end
  end
end
