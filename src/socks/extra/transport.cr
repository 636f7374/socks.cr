class Transport
  enum Side : UInt8
    Source      = 0_u8
    Destination = 1_u8
  end

  property source : IO
  property destination : IO
  getter callback : Proc(Int64, Int64, Nil)?
  getter heartbeat : Proc(Nil)?
  getter latestAliveTime : Time
  getter sentSize : Atomic(Int64)
  getter receivedSize : Atomic(Int64)
  property heartbeatInterval : Time::Span
  property aliveInterval : Time::Span
  property extraSentSize : Int32 | Int64
  property extraReceivedSize : Int32 | Int64
  getter concurrentFibers : Array(Fiber)
  getter concurrentMutex : Mutex

  def initialize(@source : IO, @destination : IO, @callback : Proc(Int64, Int64, Nil)? = nil, @heartbeat : Proc(Nil)? = nil)
    @latestAliveTime = Time.local
    @sentSize = Atomic(Int64).new -1_i64
    @receivedSize = Atomic(Int64).new -1_i64
    @heartbeatInterval = 3_i32.seconds
    @aliveInterval = 1_i32.minutes
    @extraSentSize = 0_i32
    @extraReceivedSize = 0_i32
    @concurrentFibers = [] of Fiber
    @concurrentMutex = Mutex.new :unchecked
  end

  private def latest_alive_time=(value : Time)
    @concurrentMutex.synchronize { @latestAliveTime = value }
  end

  private def latest_alive_time
    @concurrentMutex.synchronize { @latestAliveTime }
  end

  def source_tls_socket=(value : OpenSSL::SSL::Socket::Server)
    @sourceTlsSocket = value
  end

  def source_tls_socket
    @sourceTlsSocket
  end

  def source_tls_context=(value : OpenSSL::SSL::Context::Server)
    @sourceTlsContext = value
  end

  def source_tls_context
    @sourceTlsContext
  end

  def destination_tls_socket=(value : OpenSSL::SSL::Socket::Client)
    @destinationTlsSocket = value
  end

  def destination_tls_socket
    @destinationTlsSocket
  end

  def destination_tls_context=(value : OpenSSL::SSL::Context::Client)
    @destinationTlsContext = value
  end

  def destination_tls_context
    @destinationTlsContext
  end

  def finished?
    concurrentMutex.synchronize { concurrentFibers.all? { |fiber| fiber.dead? } }
  end

  def done? : Bool
    sent_done = 0_i64 <= sentSize.get
    received_done = 0_i64 <= receivedSize.get

    finished? || sent_done || received_done
  end

  def sent_done? : Bool
    sent_done = 0_i64 <= sentSize.get

    finished? || sent_done
  end

  def cleanup
    source.close rescue nil
    destination.close rescue nil

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      free_source_tls
      free_destination_tls

      break
    end
  end

  def cleanup(side : Side, free_tls : Bool)
    case side
    in .source?
      source.close rescue nil
    in .destination?
      destination.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      case side
      in .source?
        free_source_tls
      in .destination?
        free_destination_tls
      end

      break
    end
  end

  private def free_source_tls
    source_tls_socket.try &.free
    source_tls_context.try &.free
  end

  private def free_destination_tls
    destination_tls_socket.try &.free
    destination_tls_context.try &.free
  end

  def reset! : Bool
    return false unless finished?

    @concurrentMutex.synchronize do
      @latestAliveTime = Time.local
      @sentSize = Atomic(Int64).new -1_i64
      @receivedSize = Atomic(Int64).new -1_i64
      @extraSentSize = 0_i32
      @extraReceivedSize = 0_i32
      @concurrentFibers.clear
    end

    true
  end

  def perform
    self.latest_alive_time = Time.local

    sent_fiber = spawn do
      exception = nil
      count = 0_i64

      loop do
        copy_size = begin
          IO.yield_copy(src: source, dst: destination) { |count, length| self.latest_alive_time = Time.local }
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        copy_size.try { |_copy_size| count += _copy_size }
        break if aliveInterval <= (Time.local - latest_alive_time)
        break if 0_i64 <= receivedSize.get
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError

        break
      end

      count += 1_i64 if 0_i64 < count
      count = -1_i64 if count.zero?
      @sentSize.add (count + extraSentSize)
    end

    receive_fiber = spawn do
      exception = nil
      count = 0_i64

      loop do
        copy_size = begin
          IO.yield_copy(src: destination, dst: source) { |count, length| self.latest_alive_time = Time.local }
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        copy_size.try { |_copy_size| count += _copy_size }
        break if aliveInterval <= (Time.local - latest_alive_time)
        break if 0_i64 <= sentSize.get
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError

        break
      end

      count += 1_i64 if 0_i64 < count
      count = -1_i64 if count.zero?
      @receivedSize.add (count + extraReceivedSize)
    end

    mixed_fiber = spawn do
      loop do
        _sent_size = sentSize.get
        _received_size = receivedSize.get

        # Negative two means zero, such as transmission failure.
        # It can also be understood as `undefined`, `nil`.

        greater_zero = (0_i64 <= _sent_size) && (0_i64 <= _received_size)
        negative_two = (-2_i64 == _sent_size) || (-2_i64 == _received_size)

        if greater_zero || negative_two
          _sent_size = 0_i64 if -2_i64 == _sent_size
          _received_size = 0_i64 if -2_i64 == _received_size

          callback.try &.call _sent_size, _received_size

          break
        end

        next sleep 0.25_f32.seconds unless heartbeat
        next sleep 0.25_f32.seconds if (0_i64 <= _sent_size) || (0_i64 <= _received_size) || negative_two
        heartbeat.try &.call rescue nil
        sleep heartbeatInterval.seconds
      end
    end

    @concurrentMutex.synchronize do
      @concurrentFibers << sent_fiber
      @concurrentFibers << receive_fiber
      @concurrentFibers << mixed_fiber
    end
  end
end
