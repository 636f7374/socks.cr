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
    Time.unix_ms(milliseconds: @firstAliveTime.get) rescue Time.utc
  end

  def last_alive_time : Time
    Time.unix_ms(milliseconds: @lastAliveTime.get) rescue Time.utc
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

  def finished?
    concurrentMutex.synchronize { concurrentFibers.all? { |fiber| fiber.dead? } }
  end

  def any_done? : Bool
    finished? || sent_done? || receive_done?
  end

  def sent_done? : Bool
    sentDone.get.zero?
  end

  def receive_done? : Bool
    receiveDone.get.zero?
  end

  def sent_bytes : UInt64
    _destination = destination
    extra_sent_bytes = 0_u64
    extra_sent_bytes = _destination.__transfer_extra_sent_bytes if _destination.responds_to? :__transfer_extra_sent_bytes

    (@sentBytes.get + extra_sent_bytes) rescue UInt64::MAX
  end

  def received_bytes : UInt64
    _destination = destination
    extra_received_bytes = 0_u64
    extra_received_bytes = _destination.__transfer_extra_received_bytes if _destination.responds_to? :__transfer_extra_received_bytes

    (@receivedBytes.get + extra_received_bytes) rescue UInt64::MAX
  end

  def close
    @source.close rescue nil
    @destination.close rescue nil

    loop do
      next sleep 0.25_f32.seconds unless self.finished?

      break
    end
  end

  def close(sd_flag : SDFlag)
    case sd_flag
    in .source?
      @source.close rescue nil
    in .destination?
      @destination.close rescue nil
    end

    loop do
      next sleep 0.25_f32.seconds unless self.finished?

      break
    end
  end

  def check_exceed_threshold?(any_side_bytes_exceed : Bool) : Bool
    return false unless exceed_threshold_flag = exceedThresholdFlag.get
    return false if exceed_threshold_flag.none?
    return false unless _first_alive_time_unix = @firstAliveTime.get

    _socket_switch_seconds = socket_switch_seconds
    _socket_switch_bytes = socket_switch_bytes
    return false if _socket_switch_seconds.zero? && _socket_switch_bytes.zero?

    _first_alive_time = first_alive_time.dup
    timed_socket_switch = (Time.utc - _first_alive_time) > _socket_switch_seconds
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
    @firstAliveTime.set Time.local.to_unix_ms
    @lastAliveTime.set Time.local.to_unix_ms

    transfer_before_call_fiber = spawn do
      _destination = destination
      _destination.__transfer_before_call if _destination.responds_to? :__transfer_before_call
    end

    sent_fiber = spawn do
      exception = nil

      loop do
        begin
          IO.yield_copy src: @source, dst: @destination do |count, length|
            @lastAliveTime.set value: Time.local.to_unix_ms
            @sentBytes.add(value: length.to_u64) rescue @sentBytes.set(value: 0_u64)

            break if strict_check_sent_exceed_threshold? if exceedThresholdFlag.get.sent?
            break if receive_done?
          end

          break
        rescue ex : IO::CopyException
          exception = ex.cause
          _destination = destination

          # AssociateUDP will not trigger IO.yield_copy yield, so it needs to be called (last_alive_time).
          # Prevent IO::TimeoutError infinite loop.

          if _destination.responds_to? :last_alive_time
            _destination.last_alive_time.try { |_last_alive_time| @lastAliveTime.set value: _last_alive_time }
          end

          break unless ex.cause.is_a? IO::TimeoutError
          break if receive_done?
          break if strict_check_sent_exceed_threshold?
          break if aliveInterval <= (Time.utc - last_alive_time)
          next if ex.cause.is_a? IO::TimeoutError
          next unless receive_done?

          break
        end
      end

      self.sent_exception = exception
      @sentDone.set 0_u64
    end

    receive_fiber = spawn do
      exception = nil

      loop do
        begin
          IO.yield_copy src: @destination, dst: @source do |count, length|
            @lastAliveTime.set value: Time.local.to_unix_ms
            @receivedBytes.add(value: length.to_u64) rescue @receivedBytes.set(value: 0_u64)

            break if strict_check_receive_exceed_threshold? if exceedThresholdFlag.get.receive?
            break if sent_done?
          end

          break
        rescue ex : IO::CopyException
          exception = ex.cause
          _destination = destination

          # AssociateUDP will not trigger IO.yield_copy yield, so it needs to be called (last_alive_time).
          # Prevent IO::TimeoutError infinite loop.

          if _destination.responds_to? :last_alive_time
            _destination.last_alive_time.try { |_last_alive_time| @lastAliveTime.set value: _last_alive_time }
          end

          break unless ex.cause.is_a? IO::TimeoutError
          break if sent_done?
          break if strict_check_receive_exceed_threshold?
          break if aliveInterval <= (Time.utc - last_alive_time)
          next if ex.cause.is_a? IO::TimeoutError
          next unless sent_done?

          break
        end
      end

      self.receive_exception = exception
      @receiveDone.set 0_u64
    end

    interval_fiber = spawn do
      interval = 5_f32.seconds
      heartbeat_callback = heartbeatCallback
      finish_callback = finishCallback
      _last_alive_time = Time.local

      if heartbeat_callback
        loop do
          sleep interval if (Time.local - _last_alive_time) < interval

          successful = heartbeat_callback.call self, heartbeatInterval rescue nil
          @heartbeatCounter.add(value: 1_i64) rescue heartbeatCounter.set(value: 0_i64) if successful
          _last_alive_time = Time.local

          break if sent_done? || receive_done?
        end
      end

      if finish_callback
        loop do
          sleep interval if (Time.local - _last_alive_time) < interval
          break finish_callback.call self, self.sent_bytes, self.received_bytes if sent_done? && receive_done?

          _last_alive_time = Time.local
        end
      end
    end

    @concurrentMutex.synchronize do
      @concurrentFibers << transfer_before_call_fiber
      @concurrentFibers << sent_fiber
      @concurrentFibers << receive_fiber
      @concurrentFibers << interval_fiber
    end
  end
end
