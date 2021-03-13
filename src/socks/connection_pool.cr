class SOCKS::ConnectionPool
  getter clearInterval : Time::Span
  getter capacity : Int32
  getter entries : Hash(UInt64, Entry)
  getter latestCleanedUp : Time
  getter mutex : Mutex

  def initialize(@clearInterval : Time::Span = 10_i32.seconds, @capacity : Int32 = 5_i32)
    @entries = Hash(UInt64, Entry).new
    @latestCleanedUp = Time.local
    @mutex = Mutex.new :unchecked
  end

  def clear
    @mutex.synchronize do
      entries.each do |object_id, entry|
        entry.transfer.destination.close rescue nil
        entry.transfer.destination_tls_context.try &.free
        entry.transfer.destination_tls_socket.try &.free

        entries.delete object_id
      end
    end
  end

  def size : Int32
    @mutex.synchronize { entries.size }
  end

  def unshift(value : Transfer)
    inactive_entry_cleanup
    unshift object_id: value.object_id, value: value
  end

  private def unshift(object_id : UInt64, value : Transfer)
    @mutex.synchronize do
      if entry = entries[object_id]?
        entries.delete object_id

        entry.transfer.destination.close rescue nil
        entry.transfer.destination_tls_context.try &.free
        entry.transfer.destination_tls_socket.try &.free
      end

      entries[object_id] = Entry.new transfer: value
    end
  end

  private def need_cleared?
    interval = Time.local - (@mutex.synchronize { latestCleanedUp })
    interval > clearInterval
  end

  private def refresh_latest_cleaned_up
    @mutex.synchronize { @latestCleanedUp = Time.local }
  end

  def inactive_entry_cleanup
    @mutex.synchronize do
      while capacity <= entries.size
        object_id, entry = entries.first
        entries.delete object_id

        entry.transfer.destination.close rescue nil
        entry.transfer.destination_tls_context.try &.free
        entry.transfer.destination_tls_socket.try &.free
      end
    end

    return unless need_cleared?

    @mutex.synchronize do
      entries.each do |object_id, entry|
        next unless clearInterval <= (Time.local - entry.createdAt)

        entry.transfer.destination.close rescue nil
        entry.transfer.destination_tls_context.try &.free
        entry.transfer.destination_tls_socket.try &.free

        entries.delete object_id
      end
    end

    refresh_latest_cleaned_up
  end

  def get? : Transfer?
    inactive_entry_cleanup

    @mutex.synchronize do
      begin
        object_id, entry = entries.first
      rescue ex
        return nil
      end

      entries.delete object_id

      if clearInterval <= (Time.local - entry.createdAt)
        entry.transfer.destination.close rescue nil
        entry.transfer.destination_tls_context.try &.free
        entry.transfer.destination_tls_socket.try &.free

        return
      end

      entry.transfer
    end
  end

  struct Entry
    property transfer : Transfer
    property createdAt : Time

    def initialize(@transfer : Transfer)
      @createdAt = Time.local
    end
  end
end
