import mmh3
import random
import math


class CuckooFilter:
    def __init__(self, capacity, false_positive_rate=0.01, verbose=True):
        """
        Cuckoo Filter for SDN Forensic Log Storage.
        Proposed as a superior alternative to Bloom Filters because it
        supports selective deletion — crucial for forensic evidence retention.

        Key features over Bloom Filter:
        - Supports deletion without false negatives
        - Sliding window can selectively evict old benign traffic
        - Attack evidence can be preserved (marked non-evictable)
        - No catastrophic wipe needed

        Args:
            capacity: Maximum number of items the filter can hold.
            false_positive_rate: Target FPR (determines fingerprint size).
        """
        self.capacity = capacity
        self.false_positive_rate = false_positive_rate

        # Each bucket holds b=4 fingerprints (standard from Fan et al.)
        self.bucket_size = 4

        # Number of buckets needed (with guard against zero)
        self.num_buckets = max(1, capacity // self.bucket_size)

        # Fingerprint size derived from target FPR
        # From Fan et al.: FPR ≈ (2 * b) / 2^f
        # Solving for f: f = ceil(log2(2 * b / FPR))
        self.fingerprint_bits = max(
            8, math.ceil(math.log2(2 * self.bucket_size / false_positive_rate))
        )
        self.fingerprint_max = (1 << self.fingerprint_bits) - 1

        # Buckets store tuples: (fingerprint, insertion_order, is_attack, parent_sw_id)
        # parent_sw_id = the upstream switch ID that handed us this packet
        # (None for ingress hops i.e. packets arriving directly from a host)
        # This enables parent-pointer traceback (Shesha Shila style)
        self.buckets = [[] for _ in range(self.num_buckets)]

        # Max kicks before giving up inserting (cuckoo displacement)
        self.max_kicks = 500

        # Victim stash — overflow buffer for failed insertions
        self.victim_stash = []
        self.stash_size = 10

        # Item count and insertion tracking
        self.item_count = 0
        self.total_inserted = 0
        self._insertion_counter = 0

        # Tracking counters
        self.wipe_count = 0  # Should stay 0! Unlike Bloom Filter
        self.delete_count = 0
        self.memory_log = []
        self.verbose = verbose

        if verbose:
            print(f"Cuckoo Filter created!")
            print(f"  Buckets: {self.num_buckets}")
            print(f"  Bucket size: {self.bucket_size}")
            print(f"  Fingerprint: {self.fingerprint_bits} bits "
                  f"(range 1-{self.fingerprint_max})")
            print(f"  Capacity: {capacity} items")
            print(f"  Target FPR: {false_positive_rate*100:.2f}%")

    def _fingerprint(self, item):
        """
        Create a short fingerprint of the item.
        Returns value in range [1, fingerprint_max] (0 is reserved for empty).
        """
        fp = abs(mmh3.hash(str(item), 42)) % self.fingerprint_max + 1
        return fp

    def _get_buckets(self, item):
        """
        Get two possible bucket positions for an item.
        Uses partial-key cuckoo hashing from Fan et al.
        i1 = hash(item)
        i2 = i1 XOR hash(fingerprint)
        """
        i1 = abs(mmh3.hash(str(item), 0)) % self.num_buckets
        fp = self._fingerprint(item)
        i2 = abs(i1 ^ abs(mmh3.hash(str(fp), 1))) % self.num_buckets
        return i1, i2

    def insert(self, item, is_attack=False, parent_sw_id=None):
        """
        Insert an item into the Cuckoo Filter.
        When 90% full, triggers sliding window deletion of oldest
        BENIGN entries — attack evidence is preserved!

        Args:
            item: The item to insert (flow key string).
            is_attack: If True, marks this item as non-evictable by sliding window.
            parent_sw_id: ID of the upstream switch that handed us this packet
                (None for ingress from a host). Enables parent-pointer traceback.
        """
        # Sliding window when 90% full — delete oldest BENIGN entries
        if self.item_count >= self.capacity * 0.9:
            self._sliding_window_delete()

        fp = self._fingerprint(item)
        i1, i2 = self._get_buckets(item)
        self._insertion_counter += 1
        entry = (fp, self._insertion_counter, is_attack, parent_sw_id)

        # Try inserting in bucket 1
        if len(self.buckets[i1]) < self.bucket_size:
            if not any(e[0] == fp for e in self.buckets[i1]):
                self.buckets[i1].append(entry)
                self.item_count += 1
                self.total_inserted += 1
                if self.total_inserted % 1000 == 0:
                    self._log_memory()
            return True

        # Try inserting in bucket 2
        if len(self.buckets[i2]) < self.bucket_size:
            if not any(e[0] == fp for e in self.buckets[i2]):
                self.buckets[i2].append(entry)
                self.item_count += 1
                self.total_inserted += 1
                if self.total_inserted % 1000 == 0:
                    self._log_memory()
            return True

        # Both buckets full — start kicking (cuckoo behavior!)
        # Attack-aware kicks: prefer displacing benign entries over attack entries
        i = random.choice([i1, i2])
        for _ in range(self.max_kicks):
            # Prefer kicking a benign entry if one exists in this bucket
            benign_indices = [
                j for j, e in enumerate(self.buckets[i]) if not e[2]
            ]
            if benign_indices:
                kick_idx = random.choice(benign_indices)
            else:
                kick_idx = random.randrange(len(self.buckets[i]))
            kicked_entry = self.buckets[i][kick_idx]

            # Place new entry in the kicked position
            self.buckets[i][kick_idx] = entry

            # The kicked entry preserves its original insertion order
            # and attack flag — NO timestamp reset!
            entry = kicked_entry
            fp = entry[0]

            # Try to place kicked entry in its alternate bucket
            i = abs(i ^ abs(mmh3.hash(str(fp), 1))) % self.num_buckets
            if len(self.buckets[i]) < self.bucket_size:
                self.buckets[i].append(entry)
                self.item_count += 1
                self.total_inserted += 1
                return True

        # If still can't insert — put in victim stash
        if len(self.victim_stash) < self.stash_size:
            self.victim_stash.append(entry)
            self.item_count += 1
            self.total_inserted += 1
            return True

        return False

    def lookup(self, item):
        """
        Check if an item's fingerprint exists in the filter.
        Checks both candidate buckets and the victim stash.
        """
        fp = self._fingerprint(item)
        i1, i2 = self._get_buckets(item)

        if any(e[0] == fp for e in self.buckets[i1]):
            return True
        if any(e[0] == fp for e in self.buckets[i2]):
            return True
        if any(e[0] == fp for e in self.victim_stash):
            return True
        return False

    def get_parent(self, item):
        """
        Look up the item and return the parent switch ID recorded when it was
        inserted. This is what enables parent-pointer traceback:
        'which upstream router handed me this packet?'

        Returns:
            (found, parent_sw_id) where:
                found: True if the item's fingerprint was located
                parent_sw_id: the upstream switch ID (may be None for ingress)
                              If found is False, returned as None.
        """
        fp = self._fingerprint(item)
        i1, i2 = self._get_buckets(item)

        for e in self.buckets[i1]:
            if e[0] == fp:
                return True, e[3]
        for e in self.buckets[i2]:
            if e[0] == fp:
                return True, e[3]
        for e in self.victim_stash:
            if e[0] == fp:
                return True, e[3]
        return False, None

    def delete(self, item):
        """
        Delete a specific item from the filter.
        THIS IS WHAT BLOOM FILTER CANNOT DO!
        Returns True if item was found and deleted, False otherwise.
        """
        fp = self._fingerprint(item)
        i1, i2 = self._get_buckets(item)

        for idx, e in enumerate(self.buckets[i1]):
            if e[0] == fp:
                self.buckets[i1].pop(idx)
                self.item_count -= 1
                self.delete_count += 1
                return True
        for idx, e in enumerate(self.buckets[i2]):
            if e[0] == fp:
                self.buckets[i2].pop(idx)
                self.item_count -= 1
                self.delete_count += 1
                return True
        return False

    def _sliding_window_delete(self):
        """
        Delete oldest 10% of BENIGN entries.
        Attack-marked entries are PRESERVED — this is the key advantage
        over Bloom Filter's total wipe.
        """
        num_to_delete = max(1, int(self.capacity * 0.1))

        # Collect benign entries directly from buckets: (bucket_idx, entry)
        benign_entries = []
        for bucket_idx, bucket in enumerate(self.buckets):
            for entry in bucket:
                if not entry[2]:  # entry = (fp, order, is_attack, parent_sw_id)
                    benign_entries.append((bucket_idx, entry))

        # Sort by insertion order (oldest first)
        benign_entries.sort(key=lambda x: x[1][1])

        deleted = 0
        for bucket_idx, entry in benign_entries:
            if deleted >= num_to_delete:
                break
            try:
                self.buckets[bucket_idx].remove(entry)
                self.item_count -= 1
                self.delete_count += 1
                deleted += 1
            except ValueError:
                continue

        if deleted > 0 and self.verbose:
            print(f"  *** Sliding Window: Deleted {deleted} oldest "
                  f"BENIGN entries (attacks preserved!) ***")

    def _log_memory(self):
        """Log theoretical memory usage."""
        memory_kb = self.get_memory_kb()
        self.memory_log.append({
            'items': self.total_inserted,
            'memory_kb': memory_kb,
            'deletes': self.delete_count
        })

    def get_memory_kb(self):
        """
        Theoretical memory of the filter structure.
        Memory = num_buckets * bucket_size * (fingerprint_bits / 8)
        """
        return (self.num_buckets * self.bucket_size *
                (self.fingerprint_bits / 8)) / 1024

    def get_fpr(self):
        """
        Calculate theoretical FPR of the Cuckoo Filter.
        From Fan et al.: FPR = (2 * b) / 2^f
        where b = bucket_size, f = fingerprint_bits.
        """
        fpr = (2 * self.bucket_size) / (2 ** self.fingerprint_bits)
        return fpr * 100  # Return as percentage

    def get_stats(self):
        print(f"\nCuckoo Filter Stats:")
        print(f"  Items currently stored: {self.item_count}")
        print(f"  Total items ever inserted: {self.total_inserted}")
        print(f"  Total selective deletes: {self.delete_count}")
        print(f"  Total wipes: {self.wipe_count} (should be 0!)")
        print(f"  Victim stash size: {len(self.victim_stash)}")
        fpr = self.get_fpr()
        print(f"  Theoretical FPR: {fpr:.4f}%")
        print(f"  Memory used: {self.get_memory_kb():.2f} KB")


# Quick test
if __name__ == "__main__":
    cf = CuckooFilter(capacity=10, false_positive_rate=0.01)

    print("\nInserting 12 items (capacity is 10):")
    for i in range(12):
        is_atk = (i % 3 == 0)  # Mark every 3rd as attack
        cf.insert(f"packet_{i}", is_attack=is_atk)
        print(f"  Inserted packet_{i} (attack={is_atk})")

    print("\nLooking up packet_0 (attack, inserted before capacity hit):")
    print("  Found?", cf.lookup("packet_0"))

    print("\nLooking up packet_11 (recent packet):")
    print("  Found?", cf.lookup("packet_11"))

    cf.get_stats()
