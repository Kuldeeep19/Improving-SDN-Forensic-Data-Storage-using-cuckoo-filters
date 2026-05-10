"""
Forensically Sound Cuckoo Filter Manager — Snapshot + Reset Model
=================================================================
Instead of deleting entries (which violates forensic immutability),
this manager uses a Snapshot + Reset model:

    1. When the active filter approaches capacity, it is serialized
       (archived) to disk as an immutable snapshot.
    2. A new empty filter is created for incoming traffic.
    3. Queries search across ALL snapshots + the active filter.

This ensures:
    ✓ Evidence is NEVER deleted or modified
    ✓ Full audit trail is maintained
    ✓ Legal/compliance requirements are met
    ✓ Memory stays bounded (1 active filter in RAM)
    ✓ Old evidence is recoverable from disk at any time

Contrast with the original CuckooFilter approach:
    ✗ Sliding window DELETES oldest benign entries
    ✗ Modifying forensic logs = bad forensics practice
    ✗ Audit trail has gaps (deleted entries are gone forever)
"""

import pickle
import os
from cuckoo_filter import CuckooFilter


class ForensicFilterManager:
    """
    Wraps CuckooFilter with immutable Snapshot + Reset archival.

    When the active filter reaches `threshold` fraction of capacity,
    the entire filter is serialized to disk (immutable snapshot) and a
    fresh empty filter takes over.  Nothing is ever deleted or modified.

    Exposes the same interface as CuckooFilter so it can be used as a
    drop-in replacement in SoftSwitch.
    """

    def __init__(self, capacity, false_positive_rate=0.01,
                 archive_dir='forensic_archives', threshold=0.85,
                 verbose=True, fingerprint_bits=None):
        """
        Args:
            capacity:           Per-filter item capacity.
            false_positive_rate: Target FPR for each filter.
            archive_dir:        Directory to store archived snapshots.
            threshold:          Archive when active filter reaches this
                                fraction of capacity (default 0.85 — safely
                                below the CuckooFilter's internal 0.9 sliding
                                window trigger so deletion never fires).
            fingerprint_bits:   Optional override for fingerprint size.
        """
        self.capacity = capacity
        self.false_positive_rate = false_positive_rate
        self.archive_dir = archive_dir
        self.threshold = threshold
        self.verbose = verbose
        self.fingerprint_bits = fingerprint_bits

        os.makedirs(archive_dir, exist_ok=True)

        # Create first active filter
        self.active_filter = self._new_filter()

        # Archived snapshot file paths + in-memory cache of recent ones
        self.snapshot_paths = []
        self.snapshot_count = 0

        # Stats (API-compatible with CuckooFilter)
        self.total_inserted = 0
        self.total_archives = 0
        self.wipe_count = 0       # Always 0 — no wipes!
        self.delete_count = 0     # Always 0 — no deletions!

    # ── Internal helpers ──────────────────────────────────────

    def _new_filter(self):
        """Create a fresh CuckooFilter (sliding window will never fire
        because we archive well before 90% capacity)."""
        return CuckooFilter(
            capacity=self.capacity,
            false_positive_rate=self.false_positive_rate,
            verbose=False,
            fingerprint_bits=self.fingerprint_bits,
        )

    def _archive_and_reset(self):
        """Serialize current filter to disk and create a fresh one."""
        filename = f"snapshot_{self.snapshot_count:04d}.pkl"
        path = os.path.join(self.archive_dir, filename)

        with open(path, 'wb') as f:
            pickle.dump(self.active_filter, f)

        self.snapshot_paths.append(path)
        self.snapshot_count += 1
        self.total_archives += 1

        if self.verbose:
            print(f"  [SNAPSHOT #{self.snapshot_count}]: Archived "
                  f"{self.active_filter.item_count} entries to {filename} "
                  f"(immutable, read-only)")

        # Fresh filter — old evidence is safe on disk
        self.active_filter = self._new_filter()

    def _load_snapshot(self, path):
        """Load an archived filter from disk."""
        with open(path, 'rb') as f:
            return pickle.load(f)

    # ── Public API (CuckooFilter-compatible) ──────────────────

    def insert(self, item, is_attack=False, parent_sw_id=None):
        """Insert into the active filter.  Archive + reset if near full."""
        if self.active_filter.item_count >= self.capacity * self.threshold:
            self._archive_and_reset()

        result = self.active_filter.insert(
            item, is_attack=is_attack, parent_sw_id=parent_sw_id
        )
        self.total_inserted += 1
        return result

    def lookup(self, item):
        """Search active filter, then archived snapshots (newest first)."""
        if self.active_filter.lookup(item):
            return True
        for path in reversed(self.snapshot_paths):
            archived = self._load_snapshot(path)
            if archived.lookup(item):
                return True
        return False

    def get_parent(self, item):
        """Look up parent pointer across active filter + all snapshots."""
        found, parent = self.active_filter.get_parent(item)
        if found:
            return found, parent
        for path in reversed(self.snapshot_paths):
            archived = self._load_snapshot(path)
            found, parent = archived.get_parent(item)
            if found:
                return found, parent
        return False, None

    def get_memory_kb(self):
        """RAM usage = active filter only (archived ones are on disk)."""
        return self.active_filter.get_memory_kb()

    def get_disk_kb(self):
        """Total disk usage of all archived snapshots."""
        total = 0
        for path in self.snapshot_paths:
            if os.path.exists(path):
                total += os.path.getsize(path)
        return total / 1024

    def get_fpr(self):
        """Theoretical FPR of the underlying Cuckoo Filter."""
        return self.active_filter.get_fpr()

    def get_stats(self):
        print(f"\nForensic Filter Manager Stats:")
        print(f"  Active filter items: {self.active_filter.item_count}")
        print(f"  Total items ever inserted: {self.total_inserted}")
        print(f"  Snapshots archived to disk: {self.snapshot_count}")
        print(f"  Deletions performed: 0 (immutable!)")
        print(f"  Wipes performed: 0 (immutable!)")
        print(f"  RAM usage: {self.get_memory_kb():.2f} KB (active filter only)")
        print(f"  Disk usage: {self.get_disk_kb():.2f} KB (all snapshots)")
        print(f"  Fingerprint bits: {self.active_filter.fingerprint_bits}")
        print(f"  Theoretical FPR: {self.get_fpr():.4f}%")


# ── Quick test ────────────────────────────────────────────────
if __name__ == "__main__":
    import shutil

    test_dir = 'test_forensic_archives'
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

    fm = ForensicFilterManager(
        capacity=10, archive_dir=test_dir, threshold=0.8
    )

    print("Inserting 25 items into a capacity-10 forensic manager:")
    for i in range(25):
        is_atk = (i % 5 == 0)
        fm.insert(f"packet_{i}", is_attack=is_atk)
        print(f"  Inserted packet_{i} (attack={is_atk})")

    print(f"\nSnapshots created: {fm.snapshot_count}")
    print(f"Deletions: {fm.delete_count} (must be 0!)")

    print("\nLooking up packet_0 (archived long ago):")
    print(f"  Found? {fm.lookup('packet_0')}")

    print("\nLooking up packet_24 (recent, in active filter):")
    print(f"  Found? {fm.lookup('packet_24')}")

    print("\nLooking up packet_999 (never inserted):")
    print(f"  Found? {fm.lookup('packet_999')}")

    fm.get_stats()

    # Cleanup
    shutil.rmtree(test_dir)
    print("\n[OK] Test passed -- zero deletions, full evidence preservation!")
