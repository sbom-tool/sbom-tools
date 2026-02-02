//! Content hashing utilities.

use xxhash_rust::xxh3::xxh3_64;

/// Compute a content hash for arbitrary bytes
pub fn content_hash(data: &[u8]) -> u64 {
    xxh3_64(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_hash() {
        let data = b"hello world";
        let hash = content_hash(data);
        assert_ne!(hash, 0);

        // Same input should produce same hash
        assert_eq!(hash, content_hash(data));

        // Different input should produce different hash
        assert_ne!(hash, content_hash(b"hello world!"));
    }
}
