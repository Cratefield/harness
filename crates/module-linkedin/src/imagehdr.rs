//! Just enough image header parsing to enforce LinkedIn's limits before we
//! spend a request on an upload (issue #11).
//!
//! LinkedIn accepts JPEG, PNG and GIF under 36,152,320 pixels. Reading the
//! dimensions from the header is ~80 lines and no dependency; a decoder crate
//! would be a much larger surface to keep wasm-safe for the same answer. It
//! also gives us the real format, so a PNG announced as `image/jpeg` is caught
//! here rather than by LinkedIn.

/// The image formats LinkedIn's Images API accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Jpeg,
    Png,
    Gif,
}

impl Format {
    pub(crate) fn content_type(self) -> &'static str {
        match self {
            Format::Jpeg => "image/jpeg",
            Format::Png => "image/png",
            Format::Gif => "image/gif",
        }
    }

    /// The content types a client may announce for this format.
    pub(crate) fn accepts(self, content_type: &str) -> bool {
        let announced = content_type
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        match self {
            Format::Jpeg => announced == "image/jpeg" || announced == "image/jpg",
            Format::Png => announced == "image/png",
            Format::Gif => announced == "image/gif",
        }
    }
}

/// LinkedIn's documented pixel ceiling.
pub(crate) const MAX_PIXELS: u64 = 36_152_320;

/// The format and pixel dimensions of an image, from its header alone.
/// `None` when the bytes are not one of the three accepted formats or the
/// header is truncated.
pub(crate) fn inspect(bytes: &[u8]) -> Option<(Format, u32, u32)> {
    if let Some((w, h)) = png(bytes) {
        return Some((Format::Png, w, h));
    }
    if let Some((w, h)) = gif(bytes) {
        return Some((Format::Gif, w, h));
    }
    if let Some((w, h)) = jpeg(bytes) {
        return Some((Format::Jpeg, w, h));
    }
    None
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// PNG: an 8-byte signature, then an IHDR chunk whose first two fields are
/// the width and height.
fn png(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.get(..8)? != SIGNATURE {
        return None;
    }
    if bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    Some((be32(bytes, 16)?, be32(bytes, 20)?))
}

/// GIF: `GIF87a` or `GIF89a`, then a little-endian logical screen descriptor.
fn gif(bytes: &[u8]) -> Option<(u32, u32)> {
    let magic = bytes.get(..6)?;
    if magic != b"GIF87a" && magic != b"GIF89a" {
        return None;
    }
    let width = u16::from_le_bytes([*bytes.get(6)?, *bytes.get(7)?]);
    let height = u16::from_le_bytes([*bytes.get(8)?, *bytes.get(9)?]);
    Some((u32::from(width), u32::from(height)))
}

/// JPEG: walk the marker segments to the start-of-frame, which carries the
/// dimensions. Every SOF except the ones that are not frames at all.
fn jpeg(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.get(..2)? != [0xFF, 0xD8] {
        return None;
    }
    let mut at = 2usize;
    // A malformed file must not spin: every iteration advances `at`, and the
    // segment count is bounded by the file length regardless.
    while at + 4 <= bytes.len() {
        if bytes[at] != 0xFF {
            at += 1;
            continue;
        }
        let marker = *bytes.get(at + 1)?;
        // Padding and standalone markers carry no length.
        if marker == 0xFF {
            at += 1;
            continue;
        }
        if matches!(marker, 0xD8 | 0x01) || (0xD0..=0xD7).contains(&marker) {
            at += 2;
            continue;
        }
        let length = usize::from(be16(bytes, at + 2)?);
        if length < 2 {
            return None;
        }
        // SOF0..SOF15, minus DHT (0xC4), JPG (0xC8) and DAC (0xCC), which
        // share the range but are not frame headers.
        if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            let height = be16(bytes, at + 5)?;
            let width = be16(bytes, at + 7)?;
            return Some((u32::from(width), u32::from(height)));
        }
        at += 2 + length;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_bytes(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        bytes.extend_from_slice(&13u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    fn jpeg_bytes(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xD8];
        // An APP0 segment first, so the walk has to skip something.
        bytes.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        bytes.extend_from_slice(&[0u8; 14]);
        bytes.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        bytes.extend_from_slice(&height.to_be_bytes());
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        bytes
    }

    fn gif_bytes(width: u16, height: u16) -> Vec<u8> {
        let mut bytes = b"GIF89a".to_vec();
        bytes.extend_from_slice(&width.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes
    }

    #[test]
    fn reads_each_accepted_format() {
        assert_eq!(
            inspect(&png_bytes(1200, 630)),
            Some((Format::Png, 1200, 630))
        );
        assert_eq!(
            inspect(&jpeg_bytes(800, 400)),
            Some((Format::Jpeg, 800, 400))
        );
        assert_eq!(inspect(&gif_bytes(64, 48)), Some((Format::Gif, 64, 48)));
    }

    #[test]
    fn rejects_anything_else() {
        assert!(inspect(b"not an image at all").is_none());
        assert!(inspect(&[]).is_none());
        // A truncated PNG header is not a PNG.
        assert!(inspect(&png_bytes(10, 10)[..14]).is_none());
        // A JPEG that never reaches a frame header.
        assert!(inspect(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00]).is_none());
    }

    #[test]
    fn announced_type_must_match_the_bytes() {
        assert!(Format::Png.accepts("image/png"));
        assert!(Format::Jpeg.accepts("image/jpeg; charset=binary"));
        assert!(Format::Jpeg.accepts("IMAGE/JPG"));
        assert!(!Format::Png.accepts("image/jpeg"));
    }

    #[test]
    fn pixel_ceiling_is_linkedins() {
        // 36,000,000 pixels: a large image LinkedIn still accepts.
        let (_, w, h) = inspect(&png_bytes(6000, 6000)).expect("png");
        assert!(u64::from(w) * u64::from(h) < MAX_PIXELS);
        // 42,000,000: over the documented ceiling.
        let (_, w, h) = inspect(&png_bytes(7000, 6000)).expect("png");
        assert!(u64::from(w) * u64::from(h) > MAX_PIXELS);
    }
}
