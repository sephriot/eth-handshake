use bytes::{Bytes, BytesMut};

pub const MAX_RESERVED_MESSAGE_ID: u8 = 0x0f;

// TODO: Wrap it into an object

pub fn snappy_encode(item: Bytes) -> Result<BytesMut, snap::Error> {
    let mut encoder = snap::raw::Encoder::new();

    let mut compressed = BytesMut::zeroed(1 + snap::raw::max_compress_len(item.len() - 1));
    let compressed_size = encoder
        .compress(&item[1..], &mut compressed[1..])
        .map_err(|err| err)?;

    compressed.truncate(compressed_size + 1);
    compressed[0] = item[0] + MAX_RESERVED_MESSAGE_ID + 1;

    Ok(compressed)
}

pub fn snappy_decode(bytes: &[u8]) -> Result<BytesMut, snap::Error> {
    let mut decoder = snap::raw::Decoder::new();
    let decompressed_len = snap::raw::decompress_len(&bytes[1..])?;
    let mut decompress_buf = BytesMut::zeroed(decompressed_len + 1);
    decoder
        .decompress(&bytes[1..], &mut decompress_buf[1..])
        .map_err(|err| err)?;
    Ok(decompress_buf)
}
