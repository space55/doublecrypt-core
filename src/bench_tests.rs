//! Performance benchmarks for the filesystem core (in-memory block store).
//!
//! Run with: `cargo test --release bench_ -- --nocapture`
//!
//! These use `std::time::Instant` so they work on stable Rust.  The
//! `--release` flag is important — debug builds are ~10× slower due to
//! missing optimizations in crypto and serialization.

use std::sync::Arc;
use std::time::Instant;

use crate::block_store::MemoryBlockStore;
use crate::crypto::ChaChaEngine;
use crate::fs::FilesystemCore;
use crate::model::DEFAULT_BLOCK_SIZE;

// ── Helpers ──

/// Create a filesystem with `total_blocks` blocks on an in-memory store.
fn make_fs(total_blocks: u64) -> (FilesystemCore, Arc<MemoryBlockStore>) {
    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, total_blocks));
    let crypto = Arc::new(ChaChaEngine::generate().unwrap());
    let mut fs = FilesystemCore::new(store.clone(), crypto.clone());
    fs.init_filesystem().unwrap();
    (fs, store)
}

/// Create a file and fill it with `size` bytes of deterministic data.
fn create_file_with_size(fs: &mut FilesystemCore, path: &str, size: usize) {
    fs.create_file(path).unwrap();
    // Write in 128 KiB chunks (same as fio default).
    let chunk = vec![0xABu8; 128 * 1024];
    let mut offset = 0usize;
    while offset < size {
        let len = std::cmp::min(chunk.len(), size - offset);
        fs.write_file(path, offset as u64, &chunk[..len]).unwrap();
        offset += len;
    }
    fs.flush().unwrap();
}

fn human_throughput(bytes: usize, elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs_f64();
    let bps = bytes as f64 / secs;
    if bps >= 1_000_000_000.0 {
        format!("{:.1} GB/s", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.1} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} KB/s", bps / 1_000.0)
    } else {
        format!("{:.0} B/s", bps)
    }
}

fn human_latency(elapsed: std::time::Duration, ops: usize) -> String {
    let per_op = elapsed / ops as u32;
    if per_op.as_millis() > 0 {
        format!("{:.2} ms", per_op.as_secs_f64() * 1000.0)
    } else {
        format!("{:.1} µs", per_op.as_secs_f64() * 1_000_000.0)
    }
}

// ── Sequential Read Benchmarks ──

#[test]
fn bench_seq_read_128k_from_1mb() {
    let (mut fs, _) = make_fs(1024);
    create_file_with_size(&mut fs, "data.bin", 1024 * 1024);

    let iterations = 50;
    let read_size = 128 * 1024;
    let file_size = 1024 * 1024;

    let start = Instant::now();
    for i in 0..iterations {
        let offset = (i * read_size) % file_size;
        let data = fs.read_file("data.bin", offset as u64, read_size).unwrap();
        assert!(!data.is_empty());
    }
    let elapsed = start.elapsed();

    let total_bytes = iterations * read_size;
    eprintln!(
        "bench_seq_read_128k_from_1mb: {} reads, {} total, {} ({}/read)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
    );
}

#[test]
fn bench_seq_read_128k_from_64mb() {
    // 64 MiB file needs ~1024 data blocks + metadata ≈ 1040 blocks.
    let (mut fs, _) = make_fs(2048);
    create_file_with_size(&mut fs, "big.bin", 64 * 1024 * 1024);

    let iterations = 50;
    let read_size = 128 * 1024;
    let file_size = 64 * 1024 * 1024;

    let start = Instant::now();
    for i in 0..iterations {
        let offset = (i * read_size) % file_size;
        let data = fs.read_file("big.bin", offset as u64, read_size).unwrap();
        assert!(!data.is_empty());
    }
    let elapsed = start.elapsed();

    let total_bytes = iterations * read_size;
    eprintln!(
        "bench_seq_read_128k_from_64mb: {} reads, {} total, {} ({}/read)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
    );
}

#[test]
fn bench_random_read_128k_from_64mb() {
    let (mut fs, _) = make_fs(2048);
    create_file_with_size(&mut fs, "big.bin", 64 * 1024 * 1024);

    let iterations = 50;
    let read_size = 128 * 1024;
    let file_size = 64 * 1024 * 1024;

    // Pseudo-random offsets (deterministic, chunk-aligned).
    let chunk_size = DEFAULT_BLOCK_SIZE - 200;
    let offsets: Vec<u64> = (0..iterations)
        .map(|i| {
            let block = (i * 7 + 13) % (file_size / chunk_size);
            (block * chunk_size) as u64
        })
        .collect();

    let start = Instant::now();
    for &off in &offsets {
        let data = fs.read_file("big.bin", off, read_size).unwrap();
        assert!(!data.is_empty());
    }
    let elapsed = start.elapsed();

    let total_bytes = iterations * read_size;
    eprintln!(
        "bench_random_read_128k_from_64mb: {} reads, {} total, {} ({}/read)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
    );
}

// ── Sequential Write Benchmarks ──

#[test]
fn bench_seq_write_128k_to_new_file() {
    let (mut fs, store) = make_fs(2048);
    fs.create_file("write.bin").unwrap();

    let iterations = 100;
    let write_size = 128 * 1024;
    let data = vec![0xCDu8; write_size];

    let start = Instant::now();
    for i in 0..iterations {
        fs.write_file("write.bin", (i * write_size) as u64, &data)
            .unwrap();
    }
    fs.flush().unwrap();
    let elapsed = start.elapsed();

    let total_bytes = iterations * write_size;
    let writes = store.stats_writes();
    eprintln!(
        "bench_seq_write_128k_to_new: {} writes, {} total, {} ({}/write, {} block writes)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
        writes,
    );
}

#[test]
fn bench_seq_write_128k_overwrite_64mb() {
    let (mut fs, store) = make_fs(4096);
    create_file_with_size(&mut fs, "overwrite.bin", 64 * 1024 * 1024);
    let base_writes = store.stats_writes();

    let iterations = 50;
    let write_size = 128 * 1024;
    let file_size = 64 * 1024 * 1024;
    let data = vec![0xEFu8; write_size];

    let start = Instant::now();
    for i in 0..iterations {
        let offset = (i * write_size) % file_size;
        fs.write_file("overwrite.bin", offset as u64, &data)
            .unwrap();
    }
    fs.flush().unwrap();
    let elapsed = start.elapsed();

    let total_bytes = iterations * write_size;
    let block_writes = store.stats_writes() - base_writes;
    eprintln!(
        "bench_seq_write_128k_overwrite_64mb: {} writes, {} total, {} ({}/write, {} block writes)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
        block_writes,
    );
}

// ── Write + Sync (flush + fsync) ──

#[test]
fn bench_write_then_sync_128k() {
    let (mut fs, store) = make_fs(4096);
    create_file_with_size(&mut fs, "sync.bin", 64 * 1024 * 1024);
    let base_writes = store.stats_writes();

    let iterations = 20;
    let write_size = 128 * 1024;
    let data = vec![0x42u8; write_size];

    let start = Instant::now();
    for i in 0..iterations {
        fs.write_file("sync.bin", (i * write_size) as u64, &data)
            .unwrap();
        fs.sync().unwrap();
    }
    let elapsed = start.elapsed();

    let total_bytes = iterations * write_size;
    let block_writes = store.stats_writes() - base_writes;
    eprintln!(
        "bench_write_then_sync_128k: {} write+sync cycles, {} total, {} ({}/cycle, {} block writes)",
        iterations,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, iterations),
        block_writes,
    );
}

#[test]
fn bench_write_batch_then_sync() {
    let (mut fs, store) = make_fs(4096);
    create_file_with_size(&mut fs, "batch.bin", 64 * 1024 * 1024);
    let base_writes = store.stats_writes();

    let batch_size = 10;
    let batches = 5;
    let write_size = 128 * 1024;
    let data = vec![0x99u8; write_size];

    let start = Instant::now();
    for b in 0..batches {
        for i in 0..batch_size {
            let offset = (b * batch_size + i) * write_size;
            fs.write_file("batch.bin", offset as u64, &data).unwrap();
        }
        fs.sync().unwrap();
    }
    let elapsed = start.elapsed();

    let total_ops = batches * batch_size;
    let total_bytes = total_ops * write_size;
    let block_writes = store.stats_writes() - base_writes;
    eprintln!(
        "bench_write_batch_then_sync: {}x{} writes, {} total, {} ({}/write, {} block writes, {} syncs)",
        batches,
        batch_size,
        format_bytes(total_bytes),
        human_throughput(total_bytes, elapsed),
        human_latency(elapsed, total_ops),
        block_writes,
        batches,
    );
}

// ── Metadata Benchmarks ──

#[test]
fn bench_stat_file() {
    let (mut fs, _) = make_fs(2048);
    create_file_with_size(&mut fs, "stat.bin", 1024 * 1024);

    let iterations = 500;
    let start = Instant::now();
    for _ in 0..iterations {
        let entry = fs.stat("stat.bin").unwrap();
        assert_eq!(entry.size, 1024 * 1024);
    }
    let elapsed = start.elapsed();

    eprintln!(
        "bench_stat_file: {} lookups, {} ({}/lookup)",
        iterations,
        format!("{:.2} ms total", elapsed.as_secs_f64() * 1000.0),
        human_latency(elapsed, iterations),
    );
}

#[test]
fn bench_stat_vs_list_directory() {
    let (mut fs, _) = make_fs(2048);
    // Create 20 files in root.
    for i in 0..20 {
        fs.create_file(&format!("file_{:03}.bin", i)).unwrap();
        fs.write_file(&format!("file_{:03}.bin", i), 0, &[0u8; 100])
            .unwrap();
    }
    fs.flush().unwrap();

    let iterations = 200;

    // Benchmark stat() for one file.
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = fs.stat("file_010.bin").unwrap();
    }
    let stat_elapsed = start.elapsed();

    // Benchmark list_directory() to find the same file.
    let start = Instant::now();
    for _ in 0..iterations {
        let entries = fs.list_directory("").unwrap();
        let _ = entries.iter().find(|e| e.name == "file_010.bin").unwrap();
    }
    let list_elapsed = start.elapsed();

    eprintln!(
        "bench_stat_vs_list_directory ({} files, {} iterations):\n  stat():           {}\n  list_directory(): {}\n  speedup:          {:.1}x",
        20,
        iterations,
        human_latency(stat_elapsed, iterations),
        human_latency(list_elapsed, iterations),
        list_elapsed.as_secs_f64() / stat_elapsed.as_secs_f64(),
    );
}

#[test]
fn bench_create_files() {
    let (mut fs, _) = make_fs(4096);

    let count = 100;
    let start = Instant::now();
    for i in 0..count {
        fs.create_file(&format!("file_{:04}.txt", i)).unwrap();
    }
    let elapsed = start.elapsed();

    eprintln!(
        "bench_create_files: {} files, {} ({}/file)",
        count,
        format!("{:.2} ms total", elapsed.as_secs_f64() * 1000.0),
        human_latency(elapsed, count),
    );
}

#[test]
fn bench_list_directory_scaling() {
    let (fs, _) = make_fs(4096);

    for count in [10, 50, 100] {
        // Reset — create a fresh fs for each size.
        let (mut fresh_fs, _) = make_fs(4096);
        for i in 0..count {
            fresh_fs.create_file(&format!("f_{:04}.txt", i)).unwrap();
        }
        fresh_fs.flush().unwrap();

        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            let entries = fresh_fs.list_directory("").unwrap();
            assert_eq!(entries.len(), count);
        }
        let elapsed = start.elapsed();

        eprintln!(
            "bench_list_directory ({:>3} files): {} ({}/call)",
            count,
            format!("{:.2} ms total", elapsed.as_secs_f64() * 1000.0),
            human_latency(elapsed, iterations),
        );
    }
    // Suppress unused variable warning.
    let _ = fs;
}

// ── Mixed Read/Write (simulates fio rw pattern) ──

#[test]
fn bench_mixed_rw_128k() {
    let (mut fs, store) = make_fs(4096);
    create_file_with_size(&mut fs, "rw.bin", 64 * 1024 * 1024);
    let base_writes = store.stats_writes();

    let iterations = 50;
    let io_size = 128 * 1024;
    let file_size = 64 * 1024 * 1024;
    let write_data = vec![0x55u8; io_size];
    let mut total_read_bytes = 0usize;
    let mut total_write_bytes = 0usize;

    let start = Instant::now();
    for i in 0..iterations {
        let offset = (i * io_size) % file_size;
        if i % 2 == 0 {
            // Read.
            let data = fs.read_file("rw.bin", offset as u64, io_size).unwrap();
            total_read_bytes += data.len();
        } else {
            // Write.
            fs.write_file("rw.bin", offset as u64, &write_data).unwrap();
            total_write_bytes += io_size;
        }
    }
    fs.flush().unwrap();
    let elapsed = start.elapsed();

    let block_writes = store.stats_writes() - base_writes;
    eprintln!(
        "bench_mixed_rw_128k: {} ops (R:{} W:{}), {} ({}/op, {} block writes)",
        iterations,
        format_bytes(total_read_bytes),
        format_bytes(total_write_bytes),
        human_throughput(total_read_bytes + total_write_bytes, elapsed),
        human_latency(elapsed, iterations),
        block_writes,
    );
}

// ── Block-write Efficiency ──

#[test]
fn bench_write_amplification() {
    let (mut fs, store) = make_fs(4096);
    fs.create_file("amp.bin").unwrap();

    // Write 1 MiB in 128 KiB chunks, syncing after each.
    let write_size = 128 * 1024;
    let total_size = 1024 * 1024;
    let data = vec![0x77u8; write_size];
    let writes_before = store.stats_writes();

    for i in 0..(total_size / write_size) {
        fs.write_file("amp.bin", (i * write_size) as u64, &data)
            .unwrap();
        fs.sync().unwrap();
    }

    let block_writes = store.stats_writes() - writes_before;
    let data_blocks = total_size / DEFAULT_BLOCK_SIZE;
    let amplification = block_writes as f64 / data_blocks as f64;
    eprintln!(
        "bench_write_amplification: {} data blocks, {} block writes, {:.1}x amplification",
        data_blocks, block_writes, amplification,
    );
}

// ── Flush vs Sync ──

#[test]
fn bench_flush_vs_sync() {
    let (mut fs, _) = make_fs(4096);
    create_file_with_size(&mut fs, "fvsync.bin", 1024 * 1024);

    let iterations = 30;
    let write_size = 128 * 1024;
    let data = vec![0x33u8; write_size];

    // Benchmark flush (no fsync).
    let (mut fs_flush, _) = make_fs(4096);
    create_file_with_size(&mut fs_flush, "f.bin", 1024 * 1024);

    let start = Instant::now();
    for i in 0..iterations {
        fs_flush
            .write_file("f.bin", (i * write_size) as u64, &data)
            .unwrap();
        fs_flush.flush().unwrap();
    }
    let flush_elapsed = start.elapsed();

    // Benchmark sync (flush + fsync).
    let (mut fs_sync, _) = make_fs(4096);
    create_file_with_size(&mut fs_sync, "s.bin", 1024 * 1024);

    let start = Instant::now();
    for i in 0..iterations {
        fs_sync
            .write_file("s.bin", (i * write_size) as u64, &data)
            .unwrap();
        fs_sync.sync().unwrap();
    }
    let sync_elapsed = start.elapsed();

    eprintln!(
        "bench_flush_vs_sync ({} iterations):\n  flush(): {}\n  sync():  {}\n  (on MemoryBlockStore, sync == flush since fsync is a no-op)",
        iterations,
        human_latency(flush_elapsed, iterations),
        human_latency(sync_elapsed, iterations),
    );
    let _ = fs;
}

// ── Helpers ──

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
