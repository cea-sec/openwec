use anyhow::{bail, Result};
use buf_read_ext::BufReadExt;
use hyper::header::CONTENT_TYPE;
use log::debug;
use mime::Mime;
use std::io::{BufReader, Read};

use crate::kerberos;

pub fn read_multipart_body<S: Read>(
    stream: &mut S,
    boundary: &str,
    method: &kerberos::Method,
) -> Result<Vec<u8>> {
    let mut reader = BufReader::with_capacity(4096, stream);

    let mut buf: Vec<u8> = Vec::new();

    let middle_boundary = "--".to_owned() + boundary + "\r\n";
    let end_boundary = "--".to_owned() + boundary + "--\r\n";
    let lt = vec![b'\r', b'\n'];

    // Read past the initial boundary
    let (_, found) = reader.stream_until_token(middle_boundary.as_bytes(), &mut buf)?;
    if !found {
        bail!("EoF found before first boundary");
    }

    // Read first part which contains control information according
    // to RFC 1847

    // Read the headers (which should end in 2 line terminators, but do not
    // for unknown reasons). But there are only headers in this part so this
    // is fine :)
    buf.truncate(0); // start fresh
    let (_, found) = reader.stream_until_token(middle_boundary.as_bytes(), &mut buf)?;
    if !found {
        bail!("EofInPartHeaders");
    }

    // Keep the 2 line terminators as httparse will expect it
    buf.extend(lt.iter().cloned());

    // Parse the headers
    let mut header_memory = [httparse::EMPTY_HEADER; 4];
    match httparse::parse_headers(&buf, &mut header_memory)? {
        httparse::Status::Complete((_, raw_headers)) => {
            for header in raw_headers {
                debug!("Header found: {:?}", header);
                if header.name == CONTENT_TYPE {
                    let mime = std::str::from_utf8(header.value)?.parse::<Mime>()?;
                    if mime.type_() != "application" {
                        bail!("Wrong encapsulated multipart type");
                    }

                    let expected_sub_type = match method {
                        kerberos::Method::Kerberos => "HTTP-Kerberos-session-encrypted",
                        kerberos::Method::SPNEGO => "HTTP-SPNEGO-session-encrypted",
                    };
                    if mime.subtype() != expected_sub_type {
                        bail!(
                            "Wrong encapsulated multipart sub type. Expected \"{}\", found \"{}\"",
                            expected_sub_type,
                            mime.subtype()
                        );
                    }
                }
                if header.name == "OriginalContent" {
                    // This should be checked later: first we decrypt, then we
                    // try to understand what is inside ?
                    // TODO: store charset somewhere and use it to decode
                    // decrypted bytes
                    // TODO: check something with Length ?
                }
            }
        }
        httparse::Status::Partial => bail!("PartialHeaders"),
    }

    // Read Content-Type header
    buf.truncate(0); // start fresh
    let (_, found) = reader.stream_until_token(&lt, &mut buf)?;
    if !found {
        bail!("No cr lf after headers");
    }

    // Keep the 2 line terminators as httparse will expect it
    buf.extend(lt.iter().cloned());
    buf.extend(lt.iter().cloned());

    let mut header_memory = [httparse::EMPTY_HEADER; 4];
    match httparse::parse_headers(&buf, &mut header_memory)? {
        httparse::Status::Complete((_, raw_headers)) => {
            for header in raw_headers {
                debug!("Header found: {:?}", header);
                if header.name == CONTENT_TYPE {
                    let mime = std::str::from_utf8(header.value)?.parse::<Mime>()?;
                    if mime.type_() != "application" {
                        bail!("Wrong encapsulated multipart type");
                    }
                    if mime.subtype() != "octet-stream" {
                        bail!("Wrong encapsulated multipart sub type");
                    }
                }
            }
        }
        httparse::Status::Partial => bail!("PartialHeaders"),
    }

    // Read interesting data
    buf.truncate(0); // start fresh
    let (size, found) = reader.stream_until_token(end_boundary.as_bytes(), &mut buf)?;
    if !found {
        log::error!(
            "Could not find end boundary in {} bytes: {:?}",
            size,
            String::from_utf8_lossy(&buf)
        );
        bail!("EofInPart");
    }

    Ok(buf)
}

pub fn get_multipart_body(
    encrypted_payload: &[u8],
    cleartext_payload_len: usize,
    boundary: &str,
    method: &kerberos::Method,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4096);

    let middle_boundary = "--".to_owned() + boundary + "\r\n";
    let end_boundary = "--".to_owned() + boundary + "--\r\n";

    body.extend_from_slice(middle_boundary.as_bytes());
    let content_type = match method {
        kerberos::Method::Kerberos => {
            "Content-Type: application/HTTP-Kerberos-session-encrypted\r\n"
        }
        kerberos::Method::SPNEGO => "Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n",
    };
    body.extend_from_slice(content_type.as_bytes());

    let mut buffer = itoa::Buffer::new();
    body.extend_from_slice(
        ("OriginalContent: type=application/soap+xml;charset=UTF-16;Length=".to_owned()
            + buffer.format(cleartext_payload_len)
            + "\r\n")
            .as_bytes(),
    );

    body.extend_from_slice(middle_boundary.as_bytes());
    body.extend_from_slice("Content-Type: application/octet-stream\r\n".as_bytes());
    body.extend_from_slice(encrypted_payload);
    body.extend_from_slice(end_boundary.as_bytes());

    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipart_kerberos() -> Result<()> {
        let payload = "this is a very good payload".to_owned();
        let length = payload.len();
        let boundary = "super cool boundary";
        let method = kerberos::Method::Kerberos;

        let body = get_multipart_body(&payload.as_bytes(), length, boundary, &method);

        let received_payload = read_multipart_body(&mut &*body, boundary, &method)?;
        assert_eq!(payload.as_bytes(), received_payload);

        Ok(())
    }

    #[test]
    fn test_multipart_spnego() -> Result<()> {
        let payload = "this is a very bad payload".to_owned();
        let length = payload.len();
        let boundary = "super cool boundary";
        let method = kerberos::Method::SPNEGO;

        let body = get_multipart_body(&payload.as_bytes(), length, boundary, &method);

        let received_payload = read_multipart_body(&mut &*body, boundary, &method)?;
        assert_eq!(payload.as_bytes(), received_payload);

        Ok(())
    }
}
