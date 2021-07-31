class Transfer
  enum Side : UInt8
    Source      = 0_u8
    Destination = 1_u8
  end

  property source : IO
  property destination : IO
  property callback : Proc(Transfer, UInt64, UInt64, Nil)?
  property heartbeatCallback : Proc(Transfer, Time::Span, Bool)?
  getter firstAliveTime : Time?
  getter lastAliveTime : Time?
  getter sentStatus : Atomic(Int8)
  getter receivedStatus : Atomic(Int8)
  getter sentBytes : Atomic(UInt64)
  getter receivedBytes : Atomic(UInt64)
  getter heartbeatCounter : Atomic(UInt64)
  property heartbeatInterval : Time::Span
  property aliveInterval : Time::Span
  property extraSentSize : UInt64
  property extraReceivedSize : UInt64
  getter concurrentFibers : Set(Fiber)
  getter concurrentMutex : Mutex

  def initialize(@source : IO, @destination : IO, @callback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
    @firstAliveTime = nil
    @lastAliveTime = nil
    @sentStatus = Atomic(Int8).new -1_i8
    @receivedStatus = Atomic(Int8).new -1_i8
    @sentBytes = Atomic(UInt64).new 0_u64
    @receivedBytes = Atomic(UInt64).new 0_u64
    @heartbeatCounter = Atomic(UInt64).new 0_u64
    @heartbeatInterval = 3_i32.seconds
    @aliveInterval = 1_i32.minutes
    @extraSentSize = 0_u64
    @extraReceivedSize = 0_u64
    @concurrentFibers = Set(Fiber).new
    @concurrentMutex = Mutex.new :unchecked
  end

  private def first_alive_time=(value : Time)
    @concurrentMutex.synchronize { @firstAliveTime = value }
  end

  def first_alive_time
    @concurrentMutex.synchronize { @firstAliveTime }
  end

  private def last_alive_time=(value : Time)
    @concurrentMutex.synchronize { @lastAliveTime = value }
  end

  def last_alive_time
    @concurrentMutex.synchronize { @lastAliveTime ||= Time.local }
  end

  def heartbeat_counter
    @heartbeatCounter
  end

  def source_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Server))
    @sourceTlsSockets = value
  end

  def source_tls_sockets
    @sourceTlsSockets
  end

  def source_tls_contexts=(value : Set(OpenSSL::SSL::Context::Server))
    @sourceTlsContexts = value
  end

  def source_tls_contexts
    @sourceTlsContexts
  end

  def destination_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Client))
    @destinationTlsSockets = value
  end

  def destination_tls_sockets
    @destinationTlsSockets
  end

  def destination_tls_contexts=(value : Set(OpenSSL::SSL::Context::Client))
    @destinationTlsContexts = value
  end

  def destination_tls_contexts
    @destinationTlsContexts
  end

  def finished?
    concurrentMutex.synchronize { concurrentFibers.all? { |fiber| fiber.dead? } }
  end

  def done? : Bool
    sent_done = sentStatus.get.zero?
    received_done = receivedStatus.get.zero?

    finished? || sent_done || received_done
  end

  def sent_done? : Bool
    sentStatus.get.zero?
  end

  def receive_done? : Bool
    receivedStatus.get.zero?
  end

  def cleanup
    source.close rescue nil
    destination.close rescue nil

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      concurrentMutex.synchronize do
        free_source_tls
        free_destination_tls
      end

      reset_peer reset_tls: true
      break
    end
  end

  def cleanup(side : Side, free_tls : Bool, reset : Bool = true)
    case side
    in .source?
      source.close rescue nil
    in .destination?
      destination.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      concurrentMutex.synchronize do
        case side
        in .source?
          free_source_tls
        in .destination?
          free_destination_tls
        end
      end

      reset_peer side: side, reset_tls: free_tls if reset
      break
    end
  end

  private def reset_peer(reset_tls : Bool)
    @concurrentMutex.synchronize do
      closed_memory = IO::Memory.new 0_i32
      closed_memory.close

      @source = closed_memory
      @destination = closed_memory

      if reset_tls
        @sourceTlsSockets = nil
        @sourceTlsContexts = nil
        @destinationTlsSockets = nil
        @destinationTlsContexts = nil
      end
    end
  end

  private def reset_peer(side : Side, reset_tls : Bool)
    @concurrentMutex.synchronize do
      closed_memory = IO::Memory.new 0_i32
      closed_memory.close

      case side
      in .source?
        @source = closed_memory

        if reset_tls
          @sourceTlsSockets = nil
          @sourceTlsContexts = nil
        end
      in .destination?
        @destination = closed_memory

        if reset_tls
          @destinationTlsSockets = nil
          @destinationTlsContexts = nil
        end
      end
    end
  end

  private def free_source_tls
    source_tls_sockets.try &.each &.free
    source_tls_contexts.try &.each &.free

    true
  end

  private def free_destination_tls
    destination_tls_sockets.try &.each &.free
    destination_tls_contexts.try &.each &.free

    true
  end

  def reset! : Bool
    return false unless finished?

    @concurrentMutex.synchronize do
      @firstAliveTime = nil
      @lastAliveTime = nil
      @sentStatus.set -1_i8
      @receivedStatus.set -1_i8
      @sentBytes.set 0_u64
      @receivedBytes.set 0_u64
      @heartbeatCounter.set 0_u64
      @extraSentSize = 0_u64
      @extraReceivedSize = 0_u64
      @concurrentFibers.clear
    end

    true
  end

  def perform
    self.first_alive_time = Time.local
    self.last_alive_time = Time.local

    sent_fiber = spawn do
      exception = nil
      count = 0_u64

      loop do
        copy_size = begin
          IO.yield_copy src: source, dst: destination do |count, length|
            self.last_alive_time = Time.local
            @sentBytes.add(length.to_u64) rescue 0_u64
          end
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        copy_size.try { |_copy_size| count += _copy_size }
        break if aliveInterval <= (Time.local - last_alive_time)
        break if receivedStatus.get.zero?
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError

        break
      end

      @sentBytes.add(extraSentSize) rescue nil
      @sentStatus.set 0_u64
    end

    receive_fiber = spawn do
      exception = nil
      count = 0_u64

      loop do
        copy_size = begin
          IO.yield_copy src: destination, dst: source do |count, length|
            self.last_alive_time = Time.local
            @receivedBytes.add(length.to_u64) rescue 0_u64
          end
        rescue ex : IO::CopyException
          exception = ex.cause
          ex.count
        end

        copy_size.try { |_copy_size| count += _copy_size }
        break if aliveInterval <= (Time.local - last_alive_time)
        break if sentStatus.get.zero?
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError

        break
      end

      @receivedBytes.add(extraReceivedSize) rescue nil
      @receivedStatus.set 0_u64
    end

    mixed_fiber = spawn do
      loop do
        _sent_bytes, _received_bytes = Tuple.new sentBytes.get, receivedBytes.get

        if sent_done? || receive_done?
          callback.try &.call self, _sent_bytes, _received_bytes

          break
        end

        next sleep 0.25_f32.seconds unless heartbeat_callback = heartbeatCallback
        next sleep 0.25_f32.seconds if sent_done? || receive_done?

        successful = heartbeat_callback.call self, heartbeatInterval rescue nil
        @concurrentMutex.synchronize { @heartbeatCounter.add(1_i64) rescue nil } if successful
      end
    end

    @concurrentMutex.synchronize do
      @concurrentFibers << sent_fiber
      @concurrentFibers << receive_fiber
      @concurrentFibers << mixed_fiber
    end
  end
end
