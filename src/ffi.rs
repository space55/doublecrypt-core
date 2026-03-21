//! Minimal C ABI for Swift interop.
//!
//! # Handle-based API
//!
//! All functions operate on an opaque `FsHandle` obtained from `fs_create`.
//! The caller must eventually call `fs_destroy` to free the handle.
//!
//! # Buffer ownership
//!
//! - Buffers passed *into* Rust (e.g. `data` in `fs_write_file`) are borrowed
//!   for the duration of the call. The caller retains ownership.
//! - Buffers returned *from* Rust (e.g. `fs_list_root` JSON string) are allocated
//!   by Rust. The caller must free them with `fs_free_string`.
//! - For `fs_read_file`, the caller provides the output buffer and its capacity.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use crate::block_store::{DeviceBlockStore, DiskBlockStore, MemoryBlockStore};
use crate::crypto::ChaChaEngine;
use crate::error::FsErrorCode;
use crate::fs::FilesystemCore;
use crate::model::DEFAULT_BLOCK_SIZE;

/// Opaque handle to a FilesystemCore instance.
pub struct FsHandle {
    core: FilesystemCore,
}

// ── Lifecycle ──

/// Create a new in-memory filesystem handle.
///
/// `total_blocks`: number of blocks in the virtual block device.
/// `master_key`: pointer to the master encryption key bytes.
/// `master_key_len`: length of master_key in bytes (should be 32).
///
/// Returns a pointer to an opaque handle, or null on failure.
///
/// # Safety
/// `master_key` must point to `master_key_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn fs_create(
    total_blocks: u64,
    master_key: *const u8,
    master_key_len: usize,
) -> *mut FsHandle {
    if master_key.is_null() || master_key_len == 0 {
        return ptr::null_mut();
    }
    let key_slice = unsafe { std::slice::from_raw_parts(master_key, master_key_len) };

    let store = Arc::new(MemoryBlockStore::new(DEFAULT_BLOCK_SIZE, total_blocks));
    let crypto = match ChaChaEngine::new(key_slice) {
        Ok(c) => Arc::new(c),
        Err(_) => return ptr::null_mut(),
    };

    let core = FilesystemCore::new(store, crypto);
    let handle = Box::new(FsHandle { core });
    Box::into_raw(handle)
}

/// Create a filesystem handle backed by a file on disk.
///
/// `path`: null-terminated path to the image file.
/// `total_blocks`: number of blocks. Pass 0 to infer from file size.
/// `block_size`: block size in bytes. Pass 0 to use the default (65536).
/// `create_new`: if nonzero, create a new file (fails if it already exists).
///               if zero, open an existing file.
/// `master_key`: pointer to the master encryption key bytes.
/// `master_key_len`: length of master_key in bytes (should be 32).
///
/// Returns a pointer to an opaque handle, or null on failure.
///
/// # Safety
/// - `path` must be a valid null-terminated C string.
/// - `master_key` must point to `master_key_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn fs_create_disk(
    path: *const c_char,
    total_blocks: u64,
    block_size: u32,
    create_new: i32,
    master_key: *const u8,
    master_key_len: usize,
) -> *mut FsHandle {
    if master_key.is_null() || master_key_len == 0 {
        return ptr::null_mut();
    }
    let path_str = match unsafe { unsafe_cstr_to_str(path) } {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let key_slice = unsafe { std::slice::from_raw_parts(master_key, master_key_len) };

    let bs = if block_size == 0 {
        DEFAULT_BLOCK_SIZE
    } else {
        block_size as usize
    };

    let store = if create_new != 0 {
        match DiskBlockStore::create(path_str, bs, total_blocks) {
            Ok(s) => Arc::new(s),
            Err(_) => return ptr::null_mut(),
        }
    } else {
        match DiskBlockStore::open(path_str, bs, total_blocks) {
            Ok(s) => Arc::new(s),
            Err(_) => return ptr::null_mut(),
        }
    };

    let crypto = match ChaChaEngine::new(key_slice) {
        Ok(c) => Arc::new(c),
        Err(_) => return ptr::null_mut(),
    };

    let core = FilesystemCore::new(store, crypto);
    let handle = Box::new(FsHandle { core });
    Box::into_raw(handle)
}

/// Create a filesystem handle backed by a raw block device (e.g. `/dev/xvdf`).
///
/// `path`: null-terminated path to the block device.
/// `total_blocks`: number of blocks. Pass 0 to infer from the device size.
/// `block_size`: block size in bytes. Pass 0 to use the default (65536).
/// `initialize`: if nonzero, fill the device with random data first (slow on
///               large devices). If zero, open the device as-is.
/// `master_key`: pointer to the master encryption key bytes.
/// `master_key_len`: length of master_key in bytes (should be 32).
///
/// Returns a pointer to an opaque handle, or null on failure.
///
/// # Safety
/// - `path` must be a valid null-terminated C string.
/// - `master_key` must point to `master_key_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn fs_create_device(
    path: *const c_char,
    total_blocks: u64,
    block_size: u32,
    initialize: i32,
    master_key: *const u8,
    master_key_len: usize,
) -> *mut FsHandle {
    if master_key.is_null() || master_key_len == 0 {
        return ptr::null_mut();
    }
    let path_str = match unsafe { unsafe_cstr_to_str(path) } {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let key_slice = unsafe { std::slice::from_raw_parts(master_key, master_key_len) };

    let bs = if block_size == 0 {
        DEFAULT_BLOCK_SIZE
    } else {
        block_size as usize
    };

    let store = if initialize != 0 {
        match DeviceBlockStore::initialize(path_str, bs, total_blocks) {
            Ok(s) => Arc::new(s),
            Err(_) => return ptr::null_mut(),
        }
    } else {
        match DeviceBlockStore::open(path_str, bs, total_blocks) {
            Ok(s) => Arc::new(s),
            Err(_) => return ptr::null_mut(),
        }
    };

    let crypto = match ChaChaEngine::new(key_slice) {
        Ok(c) => Arc::new(c),
        Err(_) => return ptr::null_mut(),
    };

    let core = FilesystemCore::new(store, crypto);
    let handle = Box::new(FsHandle { core });
    Box::into_raw(handle)
}

/// Destroy a filesystem handle and free all associated resources.
///
/// # Safety
/// `handle` must be a valid pointer returned by `fs_create` or `fs_create_disk`,
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn fs_destroy(handle: *mut FsHandle) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
    }
}

// ── Filesystem operations ──

/// Initialize a new filesystem on the block store.
///
/// # Safety
/// `handle` must be a valid pointer returned by `fs_create`.
#[no_mangle]
pub unsafe extern "C" fn fs_init_filesystem(handle: *mut FsHandle) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    match h.core.init_filesystem() {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Open / mount an existing filesystem from the block store.
///
/// # Safety
/// `handle` must be a valid pointer returned by `fs_create`.
#[no_mangle]
pub unsafe extern "C" fn fs_open(handle: *mut FsHandle) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    match h.core.open() {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Create a file at the given path.
///
/// Parent directories must already exist.  The `name` argument may be
/// a `/`-separated path such as `"a/b/file.txt"`.
///
/// # Safety
/// `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn fs_create_file(handle: *mut FsHandle, name: *const c_char) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match h.core.create_file(name_str) {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Write data to a file at the given path.
///
/// # Safety
/// - `name` must be a valid null-terminated C string (may contain `/` separators).
/// - `data` must point to `data_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn fs_write_file(
    handle: *mut FsHandle,
    name: *const c_char,
    offset: u64,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if data.is_null() && data_len > 0 {
        return FsErrorCode::InvalidArgument as i32;
    }
    let slice = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };
    match h.core.write_file(name_str, offset, slice) {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Read file data into a caller-provided buffer.
///
/// On success, writes the actual number of bytes read to `*out_len` and returns 0.
/// If the buffer is too small, returns `BufferTooSmall` and sets `*out_len` to the required size.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
/// - `out_buf` must point to at least `buf_capacity` writable bytes.
/// - `out_len` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn fs_read_file(
    handle: *mut FsHandle,
    name: *const c_char,
    offset: u64,
    len: usize,
    out_buf: *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if out_buf.is_null() || out_len.is_null() {
        return FsErrorCode::InvalidArgument as i32;
    }

    match h.core.read_file(name_str, offset, len) {
        Ok(data) => {
            let buf_capacity = len;
            if data.len() > buf_capacity {
                unsafe { *out_len = data.len() };
                return FsErrorCode::BufferTooSmall as i32;
            }
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), out_buf, data.len());
                *out_len = data.len();
            }
            FsErrorCode::Ok as i32
        }
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// List the root directory. Returns a JSON string.
///
/// The returned string is allocated by Rust. The caller must free it with `fs_free_string`.
/// On error, returns null and writes the error code to `*out_error`.
///
/// For listing a subdirectory, use `fs_list_dir` instead.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `out_error` must be a valid pointer (or null if the caller doesn't need the error code).
#[no_mangle]
pub unsafe extern "C" fn fs_list_root(handle: *mut FsHandle, out_error: *mut i32) -> *mut c_char {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        if !out_error.is_null() {
            unsafe { *out_error = FsErrorCode::InvalidArgument as i32 };
        }
        return ptr::null_mut();
    };

    match h.core.list_directory("") {
        Ok(entries) => {
            let json = match serde_json::to_string(&entries) {
                Ok(j) => j,
                Err(_) => {
                    if !out_error.is_null() {
                        unsafe { *out_error = FsErrorCode::InternalError as i32 };
                    }
                    return ptr::null_mut();
                }
            };
            if !out_error.is_null() {
                unsafe { *out_error = FsErrorCode::Ok as i32 };
            }
            match CString::new(json) {
                Ok(cs) => cs.into_raw(),
                Err(_) => {
                    if !out_error.is_null() {
                        unsafe { *out_error = FsErrorCode::InternalError as i32 };
                    }
                    ptr::null_mut()
                }
            }
        }
        Err(ref e) => {
            if !out_error.is_null() {
                unsafe { *out_error = FsErrorCode::from(e) as i32 };
            }
            ptr::null_mut()
        }
    }
}

/// List a directory at the given path. Returns a JSON string.
///
/// Pass an empty string or `"/"` to list the root directory.
///
/// The returned string is allocated by Rust. The caller must free it with `fs_free_string`.
/// On error, returns null and writes the error code to `*out_error`.
///
/// # Safety
/// - `handle` must be a valid pointer.
/// - `path` must be a valid null-terminated C string (may contain `/` separators).
/// - `out_error` must be a valid pointer (or null if the caller doesn't need the error code).
#[no_mangle]
pub unsafe extern "C" fn fs_list_dir(
    handle: *mut FsHandle,
    path: *const c_char,
    out_error: *mut i32,
) -> *mut c_char {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        if !out_error.is_null() {
            unsafe { *out_error = FsErrorCode::InvalidArgument as i32 };
        }
        return ptr::null_mut();
    };
    let path_str = match unsafe { unsafe_cstr_to_str(path) } {
        Some(s) => s,
        None => {
            if !out_error.is_null() {
                unsafe { *out_error = FsErrorCode::InvalidArgument as i32 };
            }
            return ptr::null_mut();
        }
    };

    match h.core.list_directory(path_str) {
        Ok(entries) => {
            let json = match serde_json::to_string(&entries) {
                Ok(j) => j,
                Err(_) => {
                    if !out_error.is_null() {
                        unsafe { *out_error = FsErrorCode::InternalError as i32 };
                    }
                    return ptr::null_mut();
                }
            };
            if !out_error.is_null() {
                unsafe { *out_error = FsErrorCode::Ok as i32 };
            }
            match CString::new(json) {
                Ok(cs) => cs.into_raw(),
                Err(_) => {
                    if !out_error.is_null() {
                        unsafe { *out_error = FsErrorCode::InternalError as i32 };
                    }
                    ptr::null_mut()
                }
            }
        }
        Err(ref e) => {
            if !out_error.is_null() {
                unsafe { *out_error = FsErrorCode::from(e) as i32 };
            }
            ptr::null_mut()
        }
    }
}

/// Create a directory at the given path.
///
/// Parent directories must already exist.  The `name` argument may be
/// a `/`-separated path such as `"a/b/newdir"`.
///
/// # Safety
/// `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn fs_create_dir(handle: *mut FsHandle, name: *const c_char) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match h.core.create_directory(name_str) {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Remove a file (or empty directory) at the given path.
///
/// # Safety
/// `name` must be a valid null-terminated C string (may contain `/` separators).
#[no_mangle]
pub unsafe extern "C" fn fs_remove_file(handle: *mut FsHandle, name: *const c_char) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match h.core.remove_file(name_str) {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Rename a file or directory.  Both paths must share the same parent directory.
///
/// # Safety
/// `old_name` and `new_name` must be valid null-terminated C strings (may contain `/` separators).
#[no_mangle]
pub unsafe extern "C" fn fs_rename(
    handle: *mut FsHandle,
    old_name: *const c_char,
    new_name: *const c_char,
) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    let old_str = match unsafe_cstr_to_str(old_name) {
        Some(s) => s,
        None => return FsErrorCode::InvalidArgument as i32,
    };
    let new_str = match unsafe_cstr_to_str(new_name) {
        Some(s) => s,
        None => return FsErrorCode::InvalidArgument as i32,
    };
    match h.core.rename(old_str, new_str) {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Flush buffered writes to the block store **without** calling fsync.
///
/// Use this for FUSE `write`/`release` handlers.  Call [`fs_sync`] only
/// for explicit fsync requests.
///
/// # Safety
/// `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn fs_flush(handle: *mut FsHandle) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    match h.core.flush() {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Sync / flush the filesystem (flush + fsync).
///
/// # Safety
/// `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn fs_sync(handle: *mut FsHandle) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    match h.core.sync() {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Stat metadata for a single file/directory.
///
/// Returns `0` on success and populates the out-parameters.  Much cheaper
/// than `fs_list_dir` for FUSE `getattr` / `lookup`.
///
/// `out_size`:  file size in bytes (or 0 for directories).
/// `out_kind`:  0 = file, 1 = directory.
/// `out_inode_id`: the logical inode id.
///
/// # Safety
/// `handle`, `name`, and all `out_*` pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn fs_stat(
    handle: *mut FsHandle,
    name: *const c_char,
    out_size: *mut u64,
    out_kind: *mut i32,
    out_inode_id: *mut u64,
) -> i32 {
    let (h, name_str) = match validate_handle_and_name(handle, name) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if out_size.is_null() || out_kind.is_null() || out_inode_id.is_null() {
        return FsErrorCode::InvalidArgument as i32;
    }
    match h.core.stat(name_str) {
        Ok(entry) => {
            unsafe {
                *out_size = entry.size;
                *out_kind = match entry.kind {
                    crate::model::InodeKind::File => 0,
                    crate::model::InodeKind::Directory => 1,
                };
                *out_inode_id = entry.inode_id;
            }
            FsErrorCode::Ok as i32
        }
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Fill all unused blocks with cryptographically random data.
///
/// # Safety
/// `handle` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn fs_scrub_free_blocks(handle: *mut FsHandle) -> i32 {
    let Some(h) = (unsafe { handle.as_mut() }) else {
        return FsErrorCode::InvalidArgument as i32;
    };
    match h.core.scrub_free_blocks() {
        Ok(()) => FsErrorCode::Ok as i32,
        Err(ref e) => FsErrorCode::from(e) as i32,
    }
}

/// Free a string previously returned by `fs_list_root`.
///
/// # Safety
/// `s` must be a pointer previously returned by a `fs_*` function, or null.
#[no_mangle]
pub unsafe extern "C" fn fs_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

// ── Internal helpers ──

/// # Safety
/// `ptr` must be a valid null-terminated C string or null.
unsafe fn unsafe_cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

unsafe fn validate_handle_and_name<'a>(
    handle: *mut FsHandle,
    name: *const c_char,
) -> Result<(&'a mut FsHandle, &'a str), i32> {
    let h = unsafe { handle.as_mut() }.ok_or(FsErrorCode::InvalidArgument as i32)?;
    let name_str =
        unsafe { unsafe_cstr_to_str(name) }.ok_or(FsErrorCode::InvalidArgument as i32)?;
    Ok((h, name_str))
}
