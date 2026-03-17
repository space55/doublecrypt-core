use thiserror::Error;

/// Unified error type for the doublecrypt-core crate.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("block not found: {0}")]
    BlockNotFound(u64),

    #[error("block out of range: {0}")]
    BlockOutOfRange(u64),

    #[error("no free blocks available")]
    NoFreeBlocks,

    #[error("block size mismatch: expected {expected}, got {got}")]
    BlockSizeMismatch { expected: usize, got: usize },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("object not found: block {0}")]
    ObjectNotFound(u64),

    #[error("file not found: {0}")]
    FileNotFound(String),

    #[error("directory not found: {0}")]
    DirectoryNotFound(String),

    #[error("file already exists: {0}")]
    FileAlreadyExists(String),

    #[error("directory already exists: {0}")]
    DirectoryAlreadyExists(String),

    #[error("not a file: {0}")]
    NotAFile(String),

    #[error("not a directory: {0}")]
    NotADirectory(String),

    #[error("directory not empty: {0}")]
    DirectoryNotEmpty(String),

    #[error("name too long: {0} bytes (max {1})")]
    NameTooLong(usize, usize),

    #[error("filesystem not initialized")]
    NotInitialized,

    #[error("invalid superblock")]
    InvalidSuperblock,

    #[error("invalid root pointer")]
    InvalidRootPointer,

    #[error("data too large for single block: {0} bytes")]
    DataTooLarge(usize),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type FsResult<T> = Result<T, FsError>;

/// Integer error codes for the C ABI layer.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsErrorCode {
    Ok = 0,
    NotFound = -1,
    AlreadyExists = -2,
    NoSpace = -3,
    InvalidArgument = -4,
    NotInitialized = -5,
    IoError = -6,
    CryptoError = -7,
    InternalError = -8,
    BufferTooSmall = -9,
    NotAFile = -10,
    NotADirectory = -11,
    DirectoryNotEmpty = -12,
    NameTooLong = -13,
}

impl From<&FsError> for FsErrorCode {
    fn from(e: &FsError) -> Self {
        match e {
            FsError::BlockNotFound(_) | FsError::ObjectNotFound(_) => FsErrorCode::NotFound,
            FsError::FileNotFound(_) | FsError::DirectoryNotFound(_) => FsErrorCode::NotFound,
            FsError::FileAlreadyExists(_) | FsError::DirectoryAlreadyExists(_) => {
                FsErrorCode::AlreadyExists
            }
            FsError::NoFreeBlocks => FsErrorCode::NoSpace,
            FsError::BlockOutOfRange(_) | FsError::BlockSizeMismatch { .. } => {
                FsErrorCode::InvalidArgument
            }
            FsError::DataTooLarge(_) => FsErrorCode::NoSpace,
            FsError::NotInitialized | FsError::InvalidSuperblock | FsError::InvalidRootPointer => {
                FsErrorCode::NotInitialized
            }
            FsError::Encryption(_) | FsError::Decryption(_) => FsErrorCode::CryptoError,
            FsError::Serialization(_) | FsError::Deserialization(_) => FsErrorCode::InternalError,
            FsError::NotAFile(_) => FsErrorCode::NotAFile,
            FsError::NotADirectory(_) => FsErrorCode::NotADirectory,
            FsError::DirectoryNotEmpty(_) => FsErrorCode::DirectoryNotEmpty,
            FsError::NameTooLong(_, _) => FsErrorCode::NameTooLong,
            FsError::Internal(_) => FsErrorCode::InternalError,
        }
    }
}
