class SOCKS::ReusePool
  getter clearInterval : Time::Span
  getter capacity : Int32
  getter entries : Set(Entry)
  getter lastCleanedUp : Time
  getter mutex : Mutex

  def initialize(@clearInterval : Time::Span = 10_i32.seconds, @capacity : Int32 = 5_i32)
    @entries = Set(Entry).new
    @lastCleanedUp = Time.local
    @mutex = Mutex.new :unchecked
  end

  def clear
    @mutex.synchronize do
      entries.each do |entry|
        entries.delete entry

        transfer_destination_reset_socket entry: entry
        entry.transfer.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true
      end
    end
  end

  private def transfer_destination_reset_socket(entry : Entry) : Bool
    transfer_destination = entry.transfer.destination
    return false unless transfer_destination.is_a? Client

    transfer_destination.close rescue nil
    transfer_destination.reset_socket

    true
  end

  private def need_cleared?
    interval = Time.local - lastCleanedUp.dup
    interval > clearInterval
  end

  def inactive_entry_cleanup_mutex
    @mutex.synchronize { inactive_entry_cleanup }
  end

  private def inactive_entry_cleanup
    while capacity <= entries.size
      entry = entries.first
      entries.delete entry

      transfer_destination_reset_socket entry: entry
      entry.transfer.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true
    end

    return unless need_cleared?

    entries.each do |entry|
      next unless clearInterval <= (Time.local - entry.created_at)
      entries.delete entry

      transfer_destination_reset_socket entry: entry
      entry.transfer.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true
    end

    refresh_last_cleaned_up
  end

  private def refresh_last_cleaned_up
    @lastCleanedUp = Time.local
  end

  def size : Int32
    @mutex.synchronize { entries.size.dup }
  end

  def unshift(value : Transfer)
    @mutex.synchronize do
      inactive_entry_cleanup
      entries << Entry.new transfer: value
    end
  end

  def get? : Transfer?
    @mutex.synchronize do
      inactive_entry_cleanup

      loop do
        break unless entries_first = entries.first?
        entries.delete entries_first

        if clearInterval <= (Time.local - entries_first.created_at)
          transfer_destination_reset_socket entry: entry
          entries_first.transfer.cleanup sd_flag: Transfer::SDFlag::DESTINATION, reset: true

          next
        end

        break entries_first.transfer
      end
    end
  end

  struct Entry
    getter transfer : Transfer
    getter createdAt : Time

    def initialize(@transfer : Transfer)
      @createdAt = Time.local
    end

    def created_at : Time
      @createdAt
    end
  end
end
