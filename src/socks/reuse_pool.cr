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
        entries.delete object: entry

        entry.destination.close rescue nil
      end
    end
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

      entries.delete object: entry
      entry.destination.close rescue nil
    end

    return unless need_cleared?

    entries.each do |entry|
      next unless clearInterval <= (Time.local - entry.created_at)

      entries.delete object: entry
      entry.destination.close rescue nil
    end

    refresh_last_cleaned_up
  end

  private def refresh_last_cleaned_up
    @lastCleanedUp = Time.local
  end

  def size : Int32
    @mutex.synchronize { entries.size.dup }
  end

  def unshift(value : Enhanced::WebSocket, options : Options) : Bool
    if capacity.zero?
      value.close rescue nil

      return false
    end

    @mutex.synchronize do
      inactive_entry_cleanup
      entries << Entry.new destination: value, options: options
    end

    true
  end

  def get? : Entry?
    @mutex.synchronize do
      inactive_entry_cleanup

      loop do
        break unless entries_first = entries.first?
        entries.delete object: entries_first

        if clearInterval <= (Time.local - entries_first.created_at)
          entries_first.close rescue nil

          next
        end

        break entries_first
      end
    end
  end

  struct Entry
    getter destination : Enhanced::WebSocket
    getter options : SOCKS::Options
    getter createdAt : Time

    def initialize(@destination : Enhanced::WebSocket, @options : SOCKS::Options)
      @createdAt = Time.local
    end

    def created_at : Time
      @createdAt
    end
  end
end
