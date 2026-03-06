use std::io::{self, Read, Write};

use crate::droplet::Droplet;

/// Magic bytes identifying our file format.
const MAGIC: &[u8; 4] = b"SEF1";

/// Current file format version.
const FORMAT_VERSION: u16 = 1;

/// Serializes a `Droplet` to a binary writer.
///
/// This format is designed for sequential persistence or network transmission.
/// Note: `degree` is capped at `u16::MAX`.
///
/// Layout (Little-Endian):
///
/// | Offset | Size | Field          | Description                  |
/// |--------|------|----------------|------------------------------|
/// | 0      | 4    | magic          | "SEF1"                       |
/// | 4      | 2    | version        | Constant: 1                  |
/// | 6      | 8    | epoch_id       | Unique epoch identifier      |
/// | 14     | 8    | droplet_id     | Unique droplet identifier    |
/// | 22     | 2    | degree (D)     | Number of indices            |
/// | 24     | 4    | padded_len (L) | Payload size in bytes        |
/// | 28     | D*4  | indices        | Array of source block IDs    |
/// | 28+D*4 | L    | payload        | XOR'd data symbols           |
pub fn write_droplet<W: Write>(w: &mut W, droplet: &Droplet) -> io::Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&FORMAT_VERSION.to_le_bytes())?;
    w.write_all(&droplet.epoch_id.to_le_bytes())?;
    w.write_all(&droplet.droplet_id.to_le_bytes())?;

    let degree = droplet.indices.len() as u16;
    w.write_all(&degree.to_le_bytes())?;
    w.write_all(&droplet.padded_len.to_le_bytes())?;

    for &idx in &droplet.indices {
        w.write_all(&idx.to_le_bytes())?;
    }

    w.write_all(&droplet.payload)?;
    Ok(())
}

/// Reads and reconstructs a `Droplet` from a binary stream.
///
/// # Errors
/// Returns `InvalidData` if the magic bytes or version are incorrect.
/// Returns `UnexpectedEof` if the stream ends before the droplet is fully read.
///
/// # Security Note
/// This function allocates memory based on `degree` and `padded_len` read
/// from the stream. To prevent OOM (Out of Memory) attacks from malicious
/// data, consider wrapping this in a length-limited reader.
pub fn read_droplet<R: Read>(r: &mut R) -> io::Result<Droplet> {
    // Magic
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid magic: {:?}", magic),
        ));
    }

    // Version
    let mut buf2 = [0u8; 2];
    r.read_exact(&mut buf2)?;
    let version = u16::from_le_bytes(buf2);
    if version != FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported format version: {}", version),
        ));
    }

    // Epoch ID
    let mut buf8 = [0u8; 8];
    r.read_exact(&mut buf8)?;
    let epoch_id = u64::from_le_bytes(buf8);

    // Droplet ID
    r.read_exact(&mut buf8)?;
    let droplet_id = u64::from_le_bytes(buf8);

    // Degree
    r.read_exact(&mut buf2)?;
    let degree = u16::from_le_bytes(buf2) as usize;

    // Padded length
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4)?;
    let padded_len = u32::from_le_bytes(buf4);

    // Indices
    let mut indices = Vec::with_capacity(degree);
    for _ in 0..degree {
        r.read_exact(&mut buf4)?;
        indices.push(u32::from_le_bytes(buf4));
    }

    // Payload
    let mut payload = vec![0u8; padded_len as usize];
    r.read_exact(&mut payload)?;

    Ok(Droplet {
        epoch_id,
        droplet_id,
        indices,
        padded_len,
        payload,
    })
}

/// Write a droplet to a file at the given path.
pub fn write_droplet_file(path: &std::path::Path, droplet: &Droplet) -> io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    write_droplet(&mut file, droplet)
}

/// Read a droplet from a file at the given path.
pub fn read_droplet_file(path: &std::path::Path) -> io::Result<Droplet> {
    let mut file = std::fs::File::open(path)?;
    read_droplet(&mut file)
}

/// Generate the canonical filename for a droplet.
pub fn droplet_filename(epoch_id: u64, droplet_id: u64) -> String {
    format!("epoch_{}_droplet_{}.bin", epoch_id, droplet_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_droplet() -> Droplet {
        Droplet {
            epoch_id: 42,
            droplet_id: 7,
            indices: vec![3, 15, 99],
            padded_len: 8,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        }
    }

    #[test]
    fn test_roundtrip() {
        let original = sample_droplet();
        let mut buf = Vec::new();
        write_droplet(&mut buf, &original).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recovered = read_droplet(&mut cursor).unwrap();

        assert_eq!(recovered.epoch_id, original.epoch_id);
        assert_eq!(recovered.droplet_id, original.droplet_id);
        assert_eq!(recovered.indices, original.indices);
        assert_eq!(recovered.padded_len, original.padded_len);
        assert_eq!(recovered.payload, original.payload);
    }

    #[test]
    fn test_singleton_roundtrip() {
        let d = Droplet {
            epoch_id: 0,
            droplet_id: 0,
            indices: vec![0],
            padded_len: 4,
            payload: vec![1, 2, 3, 4],
        };
        let mut buf = Vec::new();
        write_droplet(&mut buf, &d).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recovered = read_droplet(&mut cursor).unwrap();
        assert_eq!(recovered.indices, vec![0]);
        assert_eq!(recovered.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_bad_magic() {
        let mut buf = vec![0xFF, 0xFF, 0xFF, 0xFF];
        buf.extend_from_slice(&1u16.to_le_bytes());
        let mut cursor = Cursor::new(&buf);
        let result = read_droplet(&mut cursor);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[test]
    fn test_bad_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SEF1");
        buf.extend_from_slice(&99u16.to_le_bytes());
        let mut cursor = Cursor::new(&buf);
        let result = read_droplet(&mut cursor);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_truncated_payload() {
        let d = sample_droplet();
        let mut buf = Vec::new();
        write_droplet(&mut buf, &d).unwrap();
        // Truncate: remove last 2 bytes of payload
        buf.truncate(buf.len() - 2);
        let mut cursor = Cursor::new(&buf);
        let result = read_droplet(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialized_size() {
        let d = sample_droplet();
        let mut buf = Vec::new();
        write_droplet(&mut buf, &d).unwrap();

        // Expected: 4 (magic) + 2 (version) + 8 (epoch) + 8 (droplet_id)
        //         + 2 (degree) + 4 (padded_len) + 3*4 (indices) + 8 (payload)
        let expected = 4 + 2 + 8 + 8 + 2 + 4 + 12 + 8;
        assert_eq!(buf.len(), expected);
    }

    #[test]
    fn test_droplet_filename() {
        assert_eq!(droplet_filename(0, 0), "epoch_0_droplet_0.bin");
        assert_eq!(droplet_filename(5, 42), "epoch_5_droplet_42.bin");
    }

    #[test]
    fn test_file_roundtrip() {
        let dir = std::env::temp_dir().join("fountain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_droplet.bin");

        let original = sample_droplet();
        write_droplet_file(&path, &original).unwrap();
        let recovered = read_droplet_file(&path).unwrap();

        assert_eq!(recovered.epoch_id, original.epoch_id);
        assert_eq!(recovered.droplet_id, original.droplet_id);
        assert_eq!(recovered.indices, original.indices);
        assert_eq!(recovered.payload, original.payload);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_large_droplet_roundtrip() {
        // Simulates a realistically sized droplet (~1MB payload)
        let payload_size = 1_000_000;
        let d = Droplet {
            epoch_id: 100,
            droplet_id: 999,
            indices: vec![0, 50, 100, 200, 499],
            padded_len: payload_size,
            payload: vec![0xAB; payload_size as usize],
        };

        let mut buf = Vec::new();
        write_droplet(&mut buf, &d).unwrap();

        let mut cursor = Cursor::new(&buf);
        let recovered = read_droplet(&mut cursor).unwrap();
        assert_eq!(recovered.payload.len(), payload_size as usize);
        assert_eq!(recovered.indices, vec![0, 50, 100, 200, 499]);
    }
}
