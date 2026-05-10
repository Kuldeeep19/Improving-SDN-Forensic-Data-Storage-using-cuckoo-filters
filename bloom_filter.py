import mmh3
from bitarray import bitarray
import math


class BloomFilter:
    def __init__(self, capacity, false_positive_rate=0.01, verbose=True):
        """
        Bloom Filter for SDN Forensic Log Storage.
        Based on Varun Sharma's approach for optimizing forensic data
        availability and retention of SDN forensic logs.

        Args:
            capacity: Maximum number of items before filter must be wiped.
            false_positive_rate: Target FPR (default 1% as per Varun Sharma's paper).
        """
        self.capacity = capacity
        self.false_positive_rate = false_positive_rate

        # Calculate filter size in bits: m = -(n * log(p)) / (log(2)^2)
        self.size = self._get_size(capacity, false_positive_rate)

        # Calculate number of hash functions: k = (m/n) * log(2)
        self.hash_count = self._get_hash_count(self.size, capacity)

        # The actual filter - a bit array all set to 0
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)

        # Counter to track how many items are inserted (resets on wipe)
        self.item_count = 0

        # Total items ever inserted (does NOT reset on wipe)
        self.total_inserted = 0

        # Track how many times filter was wiped (evidence loss events)
        self.wipe_count = 0

        # Memory tracking
        self.memory_log = []
        self.verbose = verbose

        if verbose:
            print(f"Bloom Filter created!")
            print(f"  Size: {self.size} bits ({self.size / 8 / 1024:.2f} KB)")
            print(f"  Hash functions: {self.hash_count}")
            print(f"  Capacity: {self.capacity} items")

    def _get_size(self, n, p):
        """Calculate optimal bit array size using standard formula."""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    def _get_hash_count(self, m, n):
        """Calculate optimal number of hash functions."""
        k = (m / n) * math.log(2)
        return max(1, int(k))

    def insert(self, item):
        """
        Insert an item into the Bloom Filter.
        If the filter is full (item_count >= capacity), it must be WIPED
        entirely — this is the fundamental limitation identified by
        Varun Sharma. All forensic evidence is lost on wipe.
        """
        # If full - WIPE everything (this is the critical flaw!)
        if self.item_count >= self.capacity:
            self._wipe()

        item_str = str(item)

        # Hash the item k times and set those bits to 1
        for seed in range(self.hash_count):
            position = abs(mmh3.hash(item_str, seed)) % self.size
            self.bit_array[position] = 1

        self.item_count += 1
        self.total_inserted += 1

        # Log memory every 1000 insertions
        if self.total_inserted % 1000 == 0:
            self._log_memory()

    def lookup(self, item):
        """
        Check if an item might exist in the filter.
        Returns False = definitely not in filter.
        Returns True  = probably in filter (may be false positive).
        """
        item_str = str(item)
        for seed in range(self.hash_count):
            position = abs(mmh3.hash(item_str, seed)) % self.size
            if self.bit_array[position] == 0:
                return False  # Definitely not in filter
        return True  # Probably in filter (could be false positive)

    def _wipe(self):
        """
        Reset the entire filter — TOTAL evidence loss!
        This is the key problem: Bloom Filters cannot selectively delete,
        so when capacity is reached, ALL data must be discarded.
        """
        self.bit_array.setall(0)
        self.item_count = 0
        self.wipe_count += 1
        if self.verbose:
            print(f"  *** BLOOM FILTER WIPED! (Wipe #{self.wipe_count}) "
                  f"- All evidence lost! ***")

    def _log_memory(self):
        """Track memory usage in KB."""
        memory_kb = self.get_memory_kb()
        self.memory_log.append({
            'items': self.total_inserted,
            'memory_kb': memory_kb,
            'wipes': self.wipe_count
        })

    def get_memory_kb(self):
        """Theoretical memory = bit array size in bytes / 1024."""
        return self.size / 8 / 1024

    def get_current_fpr(self):
        """
        Calculate current theoretical FPR based on items since last wipe.
        FPR = (1 - e^(-k*n/m))^k
        where n = items currently in filter (resets after wipe).
        """
        if self.item_count == 0:
            return 0.0
        fpr = (1 - math.exp(-self.hash_count * self.item_count / self.size)) ** self.hash_count
        return min(fpr * 100, 100.0)  # Return as percentage

    def get_stats(self):
        print(f"\nBloom Filter Stats:")
        print(f"  Items currently stored: {self.item_count}")
        print(f"  Total items ever inserted: {self.total_inserted}")
        print(f"  Total wipes: {self.wipe_count}")
        print(f"  Current FPR: {self.get_current_fpr():.4f}%")
        print(f"  Memory used: {self.size / 8 / 1024:.2f} KB")


# Quick test
if __name__ == "__main__":
    bf = BloomFilter(capacity=10, false_positive_rate=0.01)

    print("\nInserting 12 items (capacity is 10 - wipe should happen):")
    for i in range(12):
        bf.insert(f"packet_{i}")
        print(f"  Inserted packet_{i}")

    print("\nLooking up packet_0 (inserted before wipe):")
    print("  Found?", bf.lookup("packet_0"))

    print("\nLooking up packet_11 (inserted after wipe):")
    print("  Found?", bf.lookup("packet_11"))

    bf.get_stats()
