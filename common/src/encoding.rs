use anyhow::{anyhow, bail, Result};
use log::warn;

pub fn decode_utf16le(message: Vec<u8>) -> Result<String> {
    let mut decoder = encoding_rs::UTF_16LE.new_decoder();
    let mut decoded = String::with_capacity(
        decoder
            .max_utf8_buffer_length(message.len())
            .ok_or_else(|| anyhow!("Could not decode utf16 data"))?,
    );
    let (result, _, replacements) = decoder.decode_to_string(&message, &mut decoded, true);
    match result {
        encoding_rs::CoderResult::InputEmpty => (),
        _ => bail!("Failed to decode utf16 data"),
    }

    if replacements {
        warn!("Replacement character has been used to decode utf16");
    }

    Ok(decoded)
}

pub fn encode_utf16le(message: String) -> Result<Vec<u8>> {
    // encoding_rs does not support UTF16-LE encoding
    // so we retrieve an iterator of u16 values using
    // String::encode_utf16 and we expand it in little
    // endian bytes by hand
    // TODO: improve performances
    let mut res: Vec<u8> = vec![0xff, 0xfe]; // BOM is mandatory
    res.extend_from_slice(
        &message
            .encode_utf16()
            .flat_map(|x| x.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() -> Result<()> {
        let message = "This is a super message with some àçcèént你好".to_owned();

        assert_eq!(decode_utf16le(encode_utf16le(message.clone())?)?, message);

        Ok(())
    }
}
