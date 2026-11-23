//! Payload storage that records no order of arrival.
//!
//! Mail and blob payloads don't live in SQLite: SQLite puts a large row on
//! new overflow pages in write order, so a seized database would show which
//! rows arrived together. Here every payload goes into a fixed-size slot of
//! a per-size-class file, and the slot is picked uniformly at random among
//! the free ones, so where a payload sits says nothing about when it came.
//! SQLite keeps only small rows naming the slot.
//!
//! - Size classes are four per doubling (2^k times 1, 1.25, 1.5, 1.75) from
//!   4 KiB to 64 MiB, so a slot wastes at most a quarter of its size. A slot
//!   holds a 16-byte header (a random tag and the length) and the payload.
//! - A file grows (by half, at least 16 slots, at most 256 MiB at a time)
//!   only when no slot is free, and only while all slot files stay under
//!   the store's size cap (reserved before growing, so classes growing at
//!   once can't overshoot it). Growing doesn't hold the class: reads and
//!   writes of its other slots go on, only allocations wait. The new region
//!   is written with zeros at once, so a later write to a slot only
//!   overwrites the file in place: the file's metadata records nothing new
//!   (no allocation, no unwritten-extent conversion). Below the file,
//!   storage may still keep old versions and their order (SSDs, remapped
//!   disk sectors, copy-on-write filesystems, snapshots): see the README.
//!   Growth itself is visible (slots past an old end were first used after
//!   the file grew).
//! - Freeing clears the tag at once (readers stop at once) but keeps the
//!   length, which marks the slot as still to be zeroed; a background thread
//!   zeroes it all and only then makes it free again, so no request waits
//!   for zeroing. Its queue holds each slot at most once (a cleared tag can't
//!   be freed again), so it's bounded by the store's size.
//! - Writes are flushed to disk before the caller records the slot.
//! - Opening scrubs every slot no row refers to whose header isn't all zero:
//!   a tag (a crash between writing a slot and recording it) or a length
//!   alone (a crash between freeing it and zeroing it).
//! - The tag guards readers: a slot freed and reused while a download streams
//!   from it fails the tag check instead of serving another payload.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use anyhow::{Context, Result, bail};

const HEADER: u64 = 16;
const MIN_SIZE: u64 = 4 << 10;
const MAX_SIZE: u64 = 64 << 20;

/// The largest payload a slot holds.
pub const MAX_PAYLOAD: u64 = MAX_SIZE - HEADER;

/// Slot sizes, ascending: 2^k * {4, 5, 6, 7} / 4 from 4 KiB to 64 MiB.
fn sizes() -> Vec<u64> {
    let mut out = Vec::new();
    let mut base = MIN_SIZE;
    while base <= MAX_SIZE {
        for m in 4..8 {
            let s = base / 4 * m;
            if s <= MAX_SIZE {
                out.push(s);
            }
        }
        base *= 2;
    }
    out
}

/// Where a payload is: its size class, slot and tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotRef {
    pub class: u8,
    pub slot: u64,
    pub tag: u64,
}

/// The store is at its size cap.
#[derive(Debug)]
pub struct Full;

impl std::fmt::Display for Full {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the relay's payload storage is full")
    }
}

impl std::error::Error for Full {}

struct Class {
    file: Arc<File>,
    slot_size: u64,
    capacity: u64,
    free: Vec<u64>,
    /// A growth is writing the next region (allocations wait for it).
    growing: bool,
}

struct ClassCell {
    m: Mutex<Class>,
    grown: std::sync::Condvar,
}

/// The most one growth of a file adds.
const GROW_BYTES: u64 = 256 << 20;

struct Shared {
    classes: Vec<ClassCell>,
    /// Bytes of all slot files, and the most they may take.
    total: AtomicU64,
    max_total: u64,
    /// Test markers the zeroing thread has reached (`settle_for_tests`).
    markers: AtomicU64,
}

/// The background thread zeroing freed slots, and its queue.
type Zeroer = (mpsc::Sender<(u8, u64)>, std::thread::JoinHandle<()>);

pub struct SlotStore {
    shared: Arc<Shared>,
    zeroer: Option<Zeroer>,
    /// Removed on drop (a store for an in-memory relay).
    temp_dir: Option<PathBuf>,
}

impl SlotStore {
    /// Open the store in `dir`, at most `max_total` bytes of slot files;
    /// `used` lists the slots the database refers to (every other slot is
    /// free, and scrubbed if it still holds anything).
    pub fn open(dir: &Path, used: &[(u8, u64)], max_total: u64) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut classes = Vec::new();
        let mut total = 0;
        let mut scrub = Vec::new();
        for (class, slot_size) in sizes().into_iter().enumerate() {
            let path = dir.join(format!("slots-{slot_size}"));
            let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
            let capacity = file.metadata()?.len() / slot_size;
            total += capacity * slot_size;
            let mut taken = vec![false; capacity as usize];
            for &(c, s) in used {
                if c as usize == class && s < capacity {
                    taken[s as usize] = true;
                }
            }
            let mut free = Vec::new();
            for s in (0..capacity).filter(|s| !taken[*s as usize]) {
                let mut header = [0u8; HEADER as usize];
                file.read_exact_at(&mut header, s * slot_size)?;
                if header == [0; HEADER as usize] {
                    free.push(s);
                } else {
                    // Left over from a crash (a tag: written, never recorded;
                    // a length alone: freed, never zeroed). Its tag is
                    // cleared and it's zeroed in the background before it's
                    // used again.
                    file.write_all_at(&[0; 8], s * slot_size)?;
                    scrub.push((class as u8, s));
                }
            }
            classes.push(ClassCell {
                m: Mutex::new(Class { file: Arc::new(file), slot_size, capacity, free, growing: false }),
                grown: std::sync::Condvar::new(),
            });
        }
        let shared = Arc::new(Shared { classes, total: AtomicU64::new(total), max_total, markers: AtomicU64::new(0) });
        let (tx, rx) = mpsc::channel::<(u8, u64)>();
        let worker = {
            let shared = shared.clone();
            std::thread::spawn(move || {
                for (class, slot) in rx {
                    if let Err(e) = zero_and_release(&shared, class, slot) {
                        tracing::warn!("could not zero a freed payload slot (it stays unused until the next start): {e:#}");
                    }
                }
            })
        };
        for s in scrub {
            let _ = tx.send(s);
        }
        Ok(Self { shared, zeroer: Some((tx, worker)), temp_dir: None })
    }

    /// A store in a fresh temporary directory, removed when dropped.
    pub fn temp(max_total: u64) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("e2ee-relay-slots-{:016x}", rand::random::<u64>()));
        let mut s = Self::open(&dir, &[], max_total)?;
        s.temp_dir = Some(dir);
        Ok(s)
    }

    fn class_for(len: u64) -> Result<u8> {
        if len > MAX_PAYLOAD {
            bail!("payload of {len} bytes is larger than a slot ({MAX_PAYLOAD} bytes)");
        }
        let need = len + HEADER;
        Ok(sizes().iter().position(|s| *s >= need).expect("MAX_PAYLOAD fits the largest slot") as u8)
    }

    /// Reserve a random free slot for a payload of `len` bytes (its header
    /// written, its content still zero). Fails with `Full` at the size cap.
    pub fn alloc(&self, len: u64) -> Result<SlotRef> {
        let class = Self::class_for(len)?;
        let cell = &self.shared.classes[class as usize];
        let mut c = cell.m.lock().unwrap();
        while c.free.is_empty() {
            if c.growing {
                c = cell.grown.wait(c).unwrap();
                continue;
            }
            let grow = (c.capacity / 2).max(16).min((GROW_BYTES / c.slot_size).max(1));
            let bytes = grow * c.slot_size;
            // Reserve against the cap first, so concurrent growths can't
            // together go past it.
            let reserved = self.shared.total.try_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
                (t + bytes <= self.shared.max_total).then_some(t + bytes)
            });
            if reserved.is_err() {
                return Err(Full.into());
            }
            let (file, from, size) = (c.file.clone(), c.capacity, c.slot_size);
            c.growing = true;
            drop(c);
            // Zeros written without holding the class.
            let written = write_zeros(&file, from * size, bytes).and_then(|()| Ok(file.sync_data()?));
            c = cell.m.lock().unwrap();
            c.growing = false;
            cell.grown.notify_all();
            if let Err(e) = written {
                // Back to the recorded size (a partly written region
                // mustn't count as slots at the next start).
                if let Err(t) = file.set_len(from * size) {
                    tracing::warn!("could not trim a slot file after a failed growth: {t}");
                }
                self.shared.total.fetch_sub(bytes, Ordering::SeqCst);
                return Err(e);
            }
            c.capacity += grow;
            c.free.extend(from..from + grow);
        }
        let i = rand::random_range(0..c.free.len());
        let slot = c.free.swap_remove(i);
        let tag = rand::random::<u64>() | 1; // never 0, which marks a free slot
        let mut header = [0u8; HEADER as usize];
        header[..8].copy_from_slice(&tag.to_be_bytes());
        header[8..].copy_from_slice(&len.to_be_bytes());
        if let Err(e) = c.file.write_all_at(&header, slot * c.slot_size) {
            c.free.push(slot);
            return Err(e.into());
        }
        Ok(SlotRef { class, slot, tag })
    }

    /// The slot's file and offset, and its payload length, if it still holds `r`.
    fn locate(&self, r: SlotRef) -> Result<Option<(Arc<File>, u64, u64)>> {
        let c = self.shared.classes.get(r.class as usize).context("bad slot class")?.m.lock().unwrap();
        if r.slot >= c.capacity {
            return Ok(None);
        }
        let base = r.slot * c.slot_size;
        let mut header = [0u8; HEADER as usize];
        c.file.read_exact_at(&mut header, base)?;
        let tag = u64::from_be_bytes(header[..8].try_into().unwrap());
        let len = u64::from_be_bytes(header[8..].try_into().unwrap());
        Ok((tag == r.tag).then(|| (c.file.clone(), base, len)))
    }

    /// Write part of a payload, at `at` within it.
    pub fn write_at(&self, r: SlotRef, at: u64, data: &[u8]) -> Result<()> {
        let Some((file, base, len)) = self.locate(r)? else { bail!("slot was freed during the write") };
        if at + data.len() as u64 > len {
            bail!("write past the payload's length");
        }
        file.write_all_at(data, base + HEADER + at)?;
        Ok(())
    }

    /// Flush a slot's writes to disk (before recording it).
    pub fn sync(&self, r: SlotRef) -> Result<()> {
        let c = self.shared.classes[r.class as usize].m.lock().unwrap();
        let file = c.file.clone();
        drop(c);
        file.sync_data()?;
        Ok(())
    }

    /// Read up to `n` bytes of a payload from `at`; `None` if the slot no
    /// longer holds it (freed, maybe reused).
    pub fn read_at(&self, r: SlotRef, at: u64, n: usize) -> Result<Option<Vec<u8>>> {
        let Some((file, base, len)) = self.locate(r)? else { return Ok(None) };
        let n = n.min(len.saturating_sub(at) as usize);
        let mut buf = vec![0u8; n];
        file.read_exact_at(&mut buf, base + HEADER + at)?;
        // Freed while we read? Then what we read may be zeros or another
        // payload: don't serve it.
        Ok(self.locate(r)?.is_some().then_some(buf))
    }

    /// A whole (small) payload.
    pub fn read(&self, r: SlotRef, len: u64) -> Result<Option<Vec<u8>>> {
        self.read_at(r, 0, len as usize)
    }

    /// Free a slot: its header is cleared now (no reader gets its payload
    /// from here on); the rest is zeroed in the background, and only then is
    /// the slot reused. A no-op if the slot no longer holds `r`.
    pub fn free(&self, r: SlotRef) -> Result<()> {
        {
            let c = self.shared.classes[r.class as usize].m.lock().unwrap();
            let Some((file, base, _)) = (|| -> Result<_> {
                if r.slot >= c.capacity {
                    return Ok(None);
                }
                let base = r.slot * c.slot_size;
                let mut header = [0u8; HEADER as usize];
                c.file.read_exact_at(&mut header, base)?;
                Ok((u64::from_be_bytes(header[..8].try_into().unwrap()) == r.tag).then(|| (c.file.clone(), base, ())))
            })()?
            else {
                return Ok(());
            };
            // The tag only: the length stays as the mark that the slot is
            // still to be zeroed (see `open`).
            file.write_all_at(&[0; 8], base)?;
        }
        if let Some((tx, _)) = &self.zeroer {
            let _ = tx.send((r.class, r.slot));
        }
        Ok(())
    }

    /// Every byte in every slot file (tests check no plaintext is stored).
    pub fn dump_for_tests(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for c in &self.shared.classes {
            let c = c.m.lock().unwrap();
            let mut buf = vec![0u8; (c.capacity * c.slot_size) as usize];
            if c.file.read_exact_at(&mut buf, 0).is_ok() {
                out.extend(buf);
            }
        }
        out
    }

    /// Stop zeroing freed slots, as a crash right after freeing would (tests).
    #[cfg(test)]
    pub fn stop_zeroer_for_tests(&mut self) {
        if let Some((tx, worker)) = self.zeroer.take() {
            drop(tx);
            let _ = worker.join();
        }
    }

    /// Wait until every freed slot has been zeroed (tests).
    #[cfg(test)]
    pub fn settle_for_tests(&self) {
        let Some((zero, _)) = &self.zeroer else { return };
        // A marker queued after everything freed so far.
        let target = self.shared.markers.load(Ordering::SeqCst) + 1;
        let _ = zero.send((u8::MAX, u64::MAX));
        for _ in 0..1000 {
            if self.shared.markers.load(Ordering::SeqCst) >= target {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// Zero a freed slot's content, flush, and make it free again.
fn zero_and_release(shared: &Shared, class: u8, slot: u64) -> Result<()> {
    if class == u8::MAX {
        shared.markers.fetch_add(1, Ordering::SeqCst);
        return Ok(());
    }
    let (file, base, size) = {
        let c = shared.classes[class as usize].m.lock().unwrap();
        (c.file.clone(), slot * c.slot_size, c.slot_size)
    };
    // The slot isn't in the free list yet, so nothing else touches it.
    // The body first, then the header: until the zeros are on disk the
    // header's length still marks the slot as dirty, so a crash in between
    // (or the disk writing pages out of order) leaves it to the next scrub.
    write_zeros(&file, base + HEADER, size - HEADER)?;
    file.sync_data()?;
    file.write_all_at(&[0; HEADER as usize], base)?;
    file.sync_data()?;
    shared.classes[class as usize].m.lock().unwrap().free.push(slot);
    Ok(())
}

fn write_zeros(file: &File, at: u64, len: u64) -> Result<()> {
    let zeros = vec![0u8; len.min(1 << 20) as usize];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(zeros.len() as u64) as usize;
        file.write_all_at(&zeros[..n], at + done)?;
        done += n as u64;
    }
    Ok(())
}

impl Drop for SlotStore {
    fn drop(&mut self) {
        // Let the zeroing thread finish what's queued.
        if let Some((tx, worker)) = self.zeroer.take() {
            drop(tx);
            let _ = worker.join();
        }
        if let Some(d) = &self.temp_dir {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_waste_at_most_a_quarter_and_fit_a_default_chunk() {
        let s = sizes();
        assert_eq!((s[0], *s.last().unwrap()), (4 << 10, 64 << 20));
        for w in s.windows(2) {
            assert!(w[1] as f64 <= w[0] as f64 * 1.25 + 1.0, "{w:?}");
        }
        // A default pack chunk (sealed) takes a 16 MiB slot, not 32.
        let sealed = 16_515_112; // pack::sealed_len(15.5 MiB)
        assert_eq!(s[SlotStore::class_for(sealed).unwrap() as usize], 16 << 20);
    }

    #[test]
    fn payloads_round_trip_and_freed_slots_are_zeroed_and_unreadable() {
        let s = SlotStore::temp(1 << 30).unwrap();
        let a = s.alloc(5).unwrap();
        s.write_at(a, 0, b"hello").unwrap();
        s.sync(a).unwrap();
        assert_eq!(s.read(a, 5).unwrap().unwrap(), b"hello");
        s.free(a).unwrap();
        assert!(s.read(a, 5).unwrap().is_none(), "a freed slot still serves its payload");
        s.settle_for_tests();
        let dump = s.dump_for_tests();
        assert!(!dump.windows(5).any(|w| w == b"hello"), "a freed payload wasn't zeroed");
        let big = s.alloc(100_000).unwrap();
        s.write_at(big, 99_990, b"0123456789").unwrap();
        assert_eq!(s.read_at(big, 99_990, 100).unwrap().unwrap(), b"0123456789");
        assert!(s.write_at(big, 99_995, b"0123456789").is_err());
        assert!(s.alloc(MAX_PAYLOAD + 1).is_err());
    }

    #[test]
    fn the_size_cap_holds() {
        let s = SlotStore::temp(16 * (4 << 10)).unwrap();
        for _ in 0..16 {
            s.alloc(10).unwrap();
        }
        assert!(s.alloc(10).unwrap_err().downcast_ref::<Full>().is_some());
    }

    /// Growths in several classes at once: the cap is reserved before any
    /// writes, so together they never pass it.
    #[test]
    fn concurrent_growths_respect_the_cap() {
        // Classes of 64, 80, 96, 112 KiB...: a first growth is 16 slots, so
        // 1 to 1.75 MiB. A 1.5 MiB cap fits any one of the first three, never
        // two.
        let cap = 3 << 19;
        let s = Arc::new(SlotStore::temp(cap).unwrap());
        let sizes = sizes();
        let first = sizes.iter().position(|x| *x == 64 << 10).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let (s, size) = (s.clone(), sizes[first + i]);
                std::thread::spawn(move || s.alloc(size - 16).is_ok())
            })
            .collect();
        let ok = threads.into_iter().map(|t| t.join().unwrap()).filter(|x| *x).count();
        assert!(ok <= 1, "{ok} classes grew under a cap that fits one");
        assert!(s.shared.total.load(Ordering::SeqCst) <= cap);
    }

    #[test]
    fn slots_are_random_kept_across_restarts_and_leftovers_scrubbed() {
        let dir = std::env::temp_dir().join(format!("e2ee-slots-test-{:016x}", rand::random::<u64>()));
        let (used, orphan) = {
            let s = SlotStore::open(&dir, &[], 1 << 30).unwrap();
            let used: Vec<SlotRef> = (0..15).map(|_| s.alloc(10).unwrap()).collect();
            // Written but never recorded (a crash before the row).
            let orphan = s.alloc(6).unwrap();
            s.write_at(orphan, 0, b"orphan").unwrap();
            (used, orphan)
        };
        let order: Vec<u64> = used.iter().map(|r| r.slot).collect();
        assert_ne!(order, (0..15).collect::<Vec<_>>(), "slots were handed out in order");
        let s = SlotStore::open(&dir, &used.iter().map(|r| (r.class, r.slot)).collect::<Vec<_>>(), 1 << 30).unwrap();
        s.settle_for_tests();
        assert!(s.read(orphan, 6).unwrap().is_none());
        assert!(!s.dump_for_tests().windows(6).any(|w| w == b"orphan"), "a crash leftover wasn't scrubbed");
        // A crash after a free, before its zeroing: the real `free`, with
        // the zeroing thread stopped. Opening finds the body and zeroes it.
        let mut s = s;
        s.write_at(used[0], 0, b"freedxxxxx").unwrap();
        s.stop_zeroer_for_tests();
        s.free(used[0]).unwrap();
        assert!(s.read(used[0], 10).unwrap().is_none());
        drop(s);
        let rest: Vec<(u8, u64)> = used[1..].iter().map(|r| (r.class, r.slot)).collect();
        let s = SlotStore::open(&dir, &rest, 1 << 30).unwrap();
        s.settle_for_tests();
        assert!(!s.dump_for_tests().windows(7).any(|w| w == b"freedxx"), "a freed payload survived a crash");
        // The scrubbed slots are free again; the recorded ones are not.
        let next = s.alloc(10).unwrap();
        assert!(!used[1..].iter().any(|u| u.slot == next.slot));
        drop(s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
