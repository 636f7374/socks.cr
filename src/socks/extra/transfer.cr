class Transfer
  enum SDFlag : UInt8
    SOURCE      = 0_u8
    DESTINATION = 1_u8
  end

  enum SRFlag : UInt8
    SENT    = 0_u8
    RECEIVE = 1_u8
  end

  enum SocketSwitchExpressionFlag : UInt8
    OR  = 0_u8
    AND = 1_u8
  end

  enum ExceedThresholdFlag : UInt8
    NONE    = 0_u8
    SENT    = 1_u8
    RECEIVE = 2_u8
  end

  class TerminateConnection < Exception
  end

  property source : IO
  property destination : IO
  property finishCallback : Proc(Transfer, UInt64, UInt64, Nil)?
  property heartbeatCallback : Proc(Transfer, Time::Span, Bool)?
  getter firstAliveTime : Atomic(Int64)
  getter lastAliveTime : Atomic(Int64)
  getter monitorCapacity : Atomic(Int8)
  getter monitorState : Hash(SRFlag, Hash(Int64, UInt64))
  getter sentDone : Atomic(Int8)
  getter receiveDone : Atomic(Int8)
  getter sentBytes : Atomic(UInt64)
  getter receivedBytes : Atomic(UInt64)
  getter heartbeatCounter : Atomic(UInt64)
  property heartbeatInterval : Time::Span
  property aliveInterval : Time::Span
  property socketSwitchSeconds : Atomic(UInt64)
  property socketSwitchBytes : Atomic(UInt64)
  property socketSwitchExpression : Atomic(SocketSwitchExpressionFlag)
  property exceedThresholdFlag : Atomic(ExceedThresholdFlag)
  getter mutex : Mutex
  getter concurrentFibers : Set(Fiber)
  getter concurrentMutex : Mutex

  def initialize(@source : IO, @destination : IO, @finishCallback : Proc(Transfer, UInt64, UInt64, Nil)? = nil, @heartbeatCallback : Proc(Transfer, Time::Span, Bool)? = nil)
    @firstAliveTime = Atomic(Int64).new -1_i64
    @lastAliveTime = Atomic(Int64).new -1_i64
    @monitorCapacity = Atomic(Int8).new Int8::MAX
    @monitorState = Hash(SRFlag, Hash(Int64, UInt64)).new
    @sentDone = Atomic(Int8).new -1_i8
    @receiveDone = Atomic(Int8).new -1_i8
    @sentBytes = Atomic(UInt64).new 0_u64
    @receivedBytes = Atomic(UInt64).new 0_u64
    @heartbeatCounter = Atomic(UInt64).new 0_u64
    @heartbeatInterval = 3_i32.seconds
    @aliveInterval = 1_i32.minutes
    @socketSwitchSeconds = Atomic(UInt64).new 0_u64
    @socketSwitchBytes = Atomic(UInt64).new 0_u64
    @socketSwitchExpression = Atomic(SocketSwitchExpressionFlag).new SocketSwitchExpressionFlag::OR
    @exceedThresholdFlag = Atomic(ExceedThresholdFlag).new ExceedThresholdFlag::NONE
    @mutex = Mutex.new :unchecked
    @concurrentFibers = Set(Fiber).new
    @concurrentMutex = Mutex.new :unchecked
  end

  def heartbeat_counter
    @heartbeatCounter
  end

  def first_alive_time : Time
    Time.unix(seconds: @firstAliveTime.get) rescue Time.local
  end

  def last_alive_time : Time
    Time.unix(seconds: @lastAliveTime.get) rescue Time.local
  end

  def source_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Server))
    @mutex.synchronize { @sourceTlsSockets = value }
  end

  def source_tls_sockets
    @mutex.synchronize { @sourceTlsSockets }
  end

  def source_tls_contexts=(value : Set(OpenSSL::SSL::Context::Server))
    @mutex.synchronize { @sourceTlsContexts = value }
  end

  def source_tls_contexts
    @mutex.synchronize { @sourceTlsContexts }
  end

  def destination_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Client))
    @mutex.synchronize { @destinationTlsSockets = value }
  end

  def destination_tls_sockets
    @mutex.synchronize { @destinationTlsSockets }
  end

  def destination_tls_contexts=(value : Set(OpenSSL::SSL::Context::Client))
    @mutex.synchronize { @destinationTlsContexts = value }
  end

  def destination_tls_contexts
    @mutex.synchronize { @destinationTlsContexts }
  end

  def sent_exception=(value : Exception?)
    @mutex.synchronize { @sentException = value }
  end

  def sent_exception? : Exception?
    @mutex.synchronize { @sentException.dup }
  end

  def receive_exception=(value : Exception?)
    @mutex.synchronize { @receiveException = value }
  end

  def receive_exception? : Exception?
    @mutex.synchronize { @receiveException.dup }
  end

  private def socket_switch_seconds : Time::Span
    @socketSwitchSeconds.get.seconds rescue 0_i32.seconds
  end

  private def socket_switch_bytes : UInt64
    _socket_switch_bytes = @socketSwitchBytes.get
    (_socket_switch_bytes < 0_u64) ? 0_u64 : _socket_switch_bytes
  end

  {% for name in ["sent", "receive"] %}
  private def monitor_state_{{name.id}}_size : Int32?
    @mutex.synchronize do
      return unless monitor_{{name.id}}_bytes = monitorState[SRFlag::{{name.upcase.id}}]?
      monitor_{{name.id}}_bytes.size
    end
  end

  def update_monitor_{{name.id}}_bytes(value : Int)
    monitor_state_{{name.id}}_size.try do |_monitor_state_{{name.id}}_size|
      @mutex.synchronize { monitorState[SRFlag::{{name.upcase.id}}].clear } if monitorCapacity.get <= _monitor_state_{{name.id}}_size
    end

    @mutex.synchronize do
      monitor_{{name.id}}_bytes = monitorState[SRFlag::{{name.upcase.id}}]? || Hash(Int64, UInt64).new
      current_time = Time.local.at_beginning_of_second.to_unix

      {{name.id}}_bytes = monitor_{{name.id}}_bytes[current_time]? || 0_u64
      {{name.id}}_bytes += value

      monitor_{{name.id}}_bytes[current_time] = {{name.id}}_bytes
      monitorState[SRFlag::{{name.upcase.id}}] = monitor_{{name.id}}_bytes
    end

    true
  end

  def get_monitor_{{name.id}}_state(all : Bool = false) : Hash(Int64, UInt64)
    @mutex.synchronize do
      monitor_{{name.id}}_bytes = monitorState[SRFlag::{{name.upcase.id}}]?.dup || Hash(Int64, UInt64).new

      if !all && !monitor_{{name.id}}_bytes.empty?
        monitor_{{name.id}}_bytes_last_key = monitor_{{name.id}}_bytes.keys.last
        monitor_{{name.id}}_bytes_last_value = monitor_{{name.id}}_bytes[monitor_{{name.id}}_bytes_last_key]
        monitorState[SRFlag::{{name.upcase.id}}].clear
        monitorState[SRFlag::{{name.upcase.id}}][monitor_{{name.id}}_bytes_last_key] = monitor_{{name.id}}_bytes_last_value
        monitor_{{name.id}}_bytes.delete monitor_{{name.id}}_bytes_last_key
      end

      monitor_{{name.id}}_bytes
    end
  end
  {% end %}

  def reset_monitor_state : Bool
    @mutex.synchronize { @monitorState.clear }

    true
  end

  def finished?
    concurrentMutex.synchronize { concurrentFibers.all? { |fiber| fiber.dead? } }
  end

  def any_done? : Bool
    sent_done = sentDone.get.zero?
    received_done = receiveDone.get.zero?

    finished? || sent_done || received_done
  end

  def sent_done? : Bool
    sentDone.get.zero?
  end

  def receive_done? : Bool
    receiveDone.get.zero?
  end

  def cleanup
    source.close rescue nil
    destination.close rescue nil

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      free_source_tls
      free_destination_tls

      reset_socket reset_tls: true
      break
    end
  end

  def cleanup(sd_flag : SDFlag, free_tls : Bool, reset : Bool = true)
    case sd_flag
    in .source?
      source.close rescue nil
    in .destination?
      destination.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless finished = self.finished?

      case sd_flag
      in .source?
        free_source_tls
      in .destination?
        free_destination_tls
      end

      reset_socket sd_flag: sd_flag, reset_tls: free_tls if reset
      break
    end
  end

  def reset_socket(reset_tls : Bool)
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

  def reset_socket(sd_flag : SDFlag, reset_tls : Bool)
    @concurrentMutex.synchronize do
      closed_memory = IO::Memory.new 0_i32
      closed_memory.close

      case sd_flag
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

  def reset_settings!(reset_socket_switch_seconds : Bool = true, reset_socket_switch_bytes : Bool = true, reset_socket_switch_expression : Bool = true) : Bool
    return false unless finished?

    @concurrentMutex.synchronize do
      @sentException = nil
      @receiveException = nil
      @firstAliveTime.set -1_i64
      @lastAliveTime.set -1_i64
      @monitorState.clear
      @exceedThresholdFlag.set ExceedThresholdFlag::NONE
      @sentDone.set -1_i8
      @receiveDone.set -1_i8
      @sentBytes.set 0_u64
      @receivedBytes.set 0_u64
      @heartbeatCounter.set 0_u64
      @socketSwitchSeconds.set 0_u64 if reset_socket_switch_seconds
      @socketSwitchBytes.set 0_u64 if reset_socket_switch_bytes
      @socketSwitchExpression.set SocketSwitchExpressionFlag::OR if reset_socket_switch_expression
      @concurrentFibers.clear
    end

    true
  end

  def check_exceed_threshold?(any_side_bytes_exceed : Bool) : Bool
    return false unless exceed_threshold_flag = exceedThresholdFlag.get
    return false if exceed_threshold_flag.none?
    return false unless _first_alive_time_unix = @firstAliveTime.get

    _socket_switch_seconds = socket_switch_seconds
    _socket_switch_bytes = socket_switch_bytes
    return false if _socket_switch_seconds.zero? && _socket_switch_bytes.zero?

    _first_alive_time = Time.unix(seconds: _first_alive_time_unix) rescue Time.local
    timed_socket_switch = (Time.local - _first_alive_time) > _socket_switch_seconds
    _socket_switch_expression = @socketSwitchExpression.get

    if any_side_bytes_exceed
      sent_bytes_exceed = sentBytes.get > _socket_switch_bytes
      receive_bytes_exceed = receivedBytes.get > _socket_switch_bytes

      case _socket_switch_expression
      in .and?
        return true if timed_socket_switch && (sent_bytes_exceed || receive_bytes_exceed)
      in .or?
        return true if timed_socket_switch
        return true if (sent_bytes_exceed || receive_bytes_exceed)
      end

      return false
    end

    case exceed_threshold_flag
    in .sent?
      bytes_exceed = sentBytes.get > _socket_switch_bytes
    in .receive?
      bytes_exceed = receivedBytes.get > _socket_switch_bytes
    in .none?
      bytes_exceed = false
    end

    case _socket_switch_expression
    in .and?
      return true if timed_socket_switch && bytes_exceed
    in .or?
      return true if timed_socket_switch || bytes_exceed
    end

    false
  end

  {% for name in ["sent", "receive"] %}
  def strict_check_{{name.id}}_exceed_threshold? : Bool
    case exceed_threshold_flag = @exceedThresholdFlag.get
    in .sent?
      {% if name == "sent" %}
        return true if check_exceed_threshold?(any_side_bytes_exceed: true) || receive_done?
      {% else %}
        return true if sent_done?
      {% end %}
    in .receive?
      {% if name == "sent" %}
        return true if receive_done?
      {% else %}
        return true if check_exceed_threshold?(any_side_bytes_exceed: true) || sent_done?
      {% end %}
    in .none?
      {% if name == "sent" %}
        return true if receive_done?
      {% else %}
        return true if sent_done?
      {% end %}
    end

    false
  end
  {% end %}

  def perform
    @firstAliveTime.set Time.local.to_unix
    @lastAliveTime.set Time.local.to_unix

    sent_fiber = spawn do
      exception = nil

      loop do
        begin
          IO.yield_copy src: source, dst: destination do |count, length|
            @lastAliveTime.set Time.local.to_unix

            sentBytes.add(length.to_u64) rescue sentBytes.set(0_u64)
            update_monitor_sent_bytes value: length

            break if strict_check_sent_exceed_threshold? if exceedThresholdFlag.get.sent?
            break if receive_done?
          end
        rescue ex : IO::CopyException
          exception = ex.cause
        end

        break unless exception.class == IO::TimeoutError if exception
        break if receive_done? && !exception
        break if strict_check_sent_exceed_threshold?
        break if aliveInterval <= (Time.local - last_alive_time)
        break if exception.is_a?(IO::TimeoutError) && exception.try &.message.try &.starts_with?("Write")
        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        next sleep 0.05_f32.seconds unless receive_done?

        break
      end

      self.sent_exception = exception
      @sentDone.set 0_u64
    end

    receive_fiber = spawn do
      exception = nil
      last_exception_time = nil

      loop do
        begin
          IO.yield_copy src: destination, dst: source do |count, length|
            @lastAliveTime.set Time.local.to_unix

            receivedBytes.add(length.to_u64) rescue receivedBytes.set(0_u64)
            update_monitor_receive_bytes value: length

            break if strict_check_receive_exceed_threshold? if exceedThresholdFlag.get.receive?
            break if sent_done?
          end
        rescue ex : IO::CopyException
          exception = ex.cause
        end

        break unless exception.class == IO::TimeoutError if exception
        break if sent_done? && !exception
        break if strict_check_receive_exceed_threshold?
        break if aliveInterval <= (Time.local - last_alive_time)

        if exception.is_a?(IO::TimeoutError) && exception.try &.message.try &.starts_with?("Write")
          _destination = destination
          ex.try &.bytes.try { |_bytes| _destination.update_receive_rescue_buffer(slice: _bytes) if _destination.responds_to? :update_receive_rescue_buffer }

          break
        end

        next sleep 0.05_f32.seconds if exception.is_a? IO::TimeoutError
        next sleep 0.05_f32.seconds unless sent_done?

        break
      end

      self.receive_exception = exception
      @receiveDone.set 0_u64
    end

    interval_fiber = spawn do
      _last_alive_time = nil

      loop do
        next _last_alive_time = Time.local unless _last_alive_time
        sleep 0.25_f32.seconds if (Time.local - _last_alive_time) < 0.1_f32.seconds

        break finishCallback.try &.call self, sentBytes.get, receivedBytes.get if sent_done? && receive_done?
        next _last_alive_time = Time.local unless heartbeat_callback = heartbeatCallback
        next _last_alive_time = Time.local if sent_done? || receive_done?

        successful = heartbeat_callback.call self, heartbeatInterval rescue nil
        @heartbeatCounter.add(1_i64) rescue nil if successful
        _last_alive_time = Time.local
      end
    end

    @concurrentMutex.synchronize do
      @concurrentFibers << sent_fiber
      @concurrentFibers << receive_fiber
      @concurrentFibers << interval_fiber
    end
  end
end
