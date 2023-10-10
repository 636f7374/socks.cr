module SOCKS::Layer
  class TCPBinding < IO
    getter source : TCPSocket
    getter destination : TCPSocket
    getter lastAliveTime : Atomic(Int64)
    getter sentBytes : Atomic(UInt64)
    getter receivedBytes : Atomic(UInt64)
    getter running : Atomic(Int8)
    getter closed : Atomic(Int8)
    getter rwLock : Crystal::RWLock

    def initialize(@source : TCPSocket, @destination : TCPSocket)
      @lastAliveTime = Atomic(Int64).new -1_i64
      @sentBytes = Atomic(UInt64).new 0_u64
      @receivedBytes = Atomic(UInt64).new 0_u64
      @running = Atomic(Int8).new value: -1_i8
      @closed = Atomic(Int8).new value: -1_i8
      @rwLock = Crystal::RWLock.new
    end

    def running=(value : Bool)
      @rwLock.write_lock
      @running.set value: (value == true ? 0_i8 : -1_i8)
      @rwLock.write_unlock
    end

    def running? : Bool
      @rwLock.read_lock
      _running = @running.get.zero?
      @rwLock.read_unlock

      _running
    end

    def closed? : Bool
      @rwLock.read_lock
      _closed = @closed.get.zero?
      @rwLock.read_unlock

      _closed
    end

    def last_alive_time : Int64
      @lastAliveTime.get
    end

    def read(slice : Bytes) : Int32
      @rwLock.write_lock

      if @running.get.zero? || @closed.get.zero?
        @rwLock.write_unlock
        sleep 1_i32.seconds

        return 0_i32
      end

      @running.set value: 0_i8
      @rwLock.write_unlock

      spawn do
        loop do
          begin
            IO.yield_copy src: @source, dst: @destination do |count, length|
              @rwLock.write_lock
              @lastAliveTime.set value: Time.local.to_unix_ms
              @sentBytes.add(value: length.to_u64) rescue @sentBytes.set(value: 0_u64)
              @rwLock.write_unlock
            end
          rescue ex : IO::TimeoutError
            next
          rescue ex
            self.running = false
          end

          self.running = false
          break
        end
      end

      spawn do
        loop do
          begin
            IO.yield_copy src: @destination, dst: @source do |count, length|
              @rwLock.write_lock
              @lastAliveTime.set value: Time.local.to_unix_ms
              @receivedBytes.add(value: length.to_u64) rescue @receivedBytes.set(value: 0_u64)
              @rwLock.write_unlock
            end
          rescue ex : IO::TimeoutError
            next
          rescue ex
          end

          self.running = false
          break
        end
      end

      loop do
        next sleep 0.5_f32.seconds if running?

        break
      end

      0_i32
    end

    def write(slice : Bytes) : Nil
    end

    def close
      @rwLock.write_lock

      if @closed.get.zero?
        @rwLock.write_unlock

        return
      end

      @running.set value: -1_i8
      @closed.set value: 0_i8
      @source.close rescue nil
      @destination.close rescue nil

      @rwLock.write_unlock
    end
  end
end

require "crystal/rw_lock"
