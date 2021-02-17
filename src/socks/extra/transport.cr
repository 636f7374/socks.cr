class Transport
  enum Side : UInt8
    Source      = 0_u8
    Destination = 1_u8
  end

  enum Reliable : UInt8
    Half        = 0_u8
    Full        = 1_u8
    Source      = 2_u8
    Destination = 3_u8
  end

  getter source : IO
  getter destination : IO
  getter callback : Proc(Int64, Int64, Nil)?
  getter heartbeat : Proc(Nil)?
  getter mutex : Mutex
  getter workerFibers : Array(Fiber)
  property reliable : Reliable

  def initialize(@source : IO, @destination : IO, @callback : Proc(Int64, Int64, Nil)? = nil, @heartbeat : Proc(Nil)? = nil)
    @mutex = Mutex.new :unchecked
    @workerFibers = [] of Fiber
    @reliable = Reliable::Full
  end

  def destination_tls_context=(value : OpenSSL::SSL::Context::Client)
    @destinationTlsContext = value
  end

  def destination_tls_context
    @destinationTlsContext
  end

  def destination_tls_socket=(value : OpenSSL::SSL::Socket::Client)
    @destinationTlsSocket = value
  end

  def destination_tls_socket
    @destinationTlsSocket
  end

  def source_tls_context=(value : OpenSSL::SSL::Context::Server)
    @sourceTlsContext = value
  end

  def source_tls_context
    @sourceTlsContext
  end

  def source_tls_socket=(value : OpenSSL::SSL::Socket::Server)
    @sourceTlsSocket = value
  end

  def source_tls_socket
    @sourceTlsSocket
  end

  def heartbeat_interval=(value : Time::Span)
    @heartbeatInterval = value
  end

  def heartbeat_interval
    @heartbeatInterval ||= 3_i32.seconds
  end

  private def sent_size=(value : Int64)
    @mutex.synchronize { @sentSize = value }
  end

  def sent_size
    @mutex.synchronize { @sentSize }
  end

  private def received_size=(value : Int64)
    @mutex.synchronize { @receivedSize = value }
  end

  def received_size
    @mutex.synchronize { @receivedSize }
  end

  private def latest_alive=(value : Time)
    @mutex.synchronize { @latestAlive = value }
  end

  private def latest_alive
    @mutex.synchronize { @latestAlive }
  end

  def alive_interval=(value : Time::Span)
    @aliveInterval = value
  end

  def alive_interval
    @aliveInterval || 1_i32.minutes
  end

  def extra_sent_size=(value : Int32 | Int64)
    @extraUploadedSize = value
  end

  def extra_sent_size
    @extraUploadedSize || 0_i32
  end

  def extra_received_size=(value : Int32 | Int64)
    @extraReceivedSize = value
  end

  def extra_received_size
    @extraReceivedSize || 0_i32
  end

  def finished?
    dead_count = @mutex.synchronize { workerFibers.count { |fiber| fiber.dead? } }
    all_task_size = @mutex.synchronize { workerFibers.size }

    dead_count == all_task_size
  end

  def reliable_status(reliable : Reliable = self.reliable)
    ->do
      case reliable
      in .half?
        self.sent_size || self.received_size
      in .full?
        self.sent_size && self.received_size
      in .source?
        self.sent_size
      in .destination?
        self.received_size
      end
    end
  end

  def cleanup_all
    source.close rescue nil
    destination.close rescue nil

    loop do
      finished = self.finished?

      if finished
        free_source_tls
        free_destination_tls

        break
      end

      sleep 0.25_f32
    end
  end

  def cleanup_side(side : Side, free_tls : Bool)
    case side
    in .source?
      source.close rescue nil
    in .destination?
      destination.close rescue nil
    end

    loop do
      finished = self.finished?

      if finished
        case side
        in .source?
          free_source_tls
        in .destination?
          free_destination_tls
        end

        break
      end

      sleep 0.25_f32
    end
  end

  def free_source_tls
    source_tls_socket.try &.free
    source_tls_context.try &.free
  end

  def free_destination_tls
    destination_tls_socket.try &.free
    destination_tls_context.try &.free
  end

  def update_latest_alive
    self.latest_alive = Time.local
  end

  def add_worker_fiber(fiber : Fiber)
    @mutex.synchronize { @workerFibers << fiber }
  end

  def perform
    update_latest_alive

    sent_fiber = spawn do
      exception = nil
      count = 0_i64

      loop do
        size = begin
          IO.super_copy(source, destination) { update_latest_alive }
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        size.try { |_size| count += _size }

        break unless _latest_alive = latest_alive
        break if alive_interval <= (Time.local - _latest_alive)
        break if received_size && exception

        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        break
      end

      self.sent_size = (count || 0_i64) + extra_sent_size
    end

    receive_fiber = spawn do
      exception = nil
      count = 0_i64

      loop do
        size = begin
          IO.super_copy(destination, source) { update_latest_alive }
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        size.try { |_size| count += _size }

        break unless _latest_alive = latest_alive
        break if alive_interval <= (Time.local - _latest_alive)
        break if sent_size && exception

        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        break
      end

      self.received_size = (count || 0_i64) + extra_received_size
    end

    mixed_fiber = spawn do
      loop do
        _sent_size = sent_size
        _received_size = received_size

        if _sent_size && _received_size
          break callback.try &.call _sent_size, _received_size
        end

        next sleep 0.25_f32.seconds unless heartbeat
        next sleep 0.25_f32.seconds if sent_size || received_size

        heartbeat.try &.call rescue nil
        sleep heartbeat_interval.seconds
      end
    end

    add_worker_fiber sent_fiber
    add_worker_fiber receive_fiber
    add_worker_fiber mixed_fiber
  end
end
