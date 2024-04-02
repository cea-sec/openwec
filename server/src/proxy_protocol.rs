// A lot of the following code comes from
// https://github.com/valorem-labs-inc/hyper-server.
// It was not used as a dependency because the read_proxy_header function cannot
// be used outside of the crate.

// As stated by its license (MIT), we include below its copyright notice and
// permission notice:
//
// Copyright 2021 Axum Server Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use ppp::v1;
use ppp::v2;
use ppp::HeaderResult;
use std::net::IpAddr;
use std::{io, net::SocketAddr};
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

/// The length of a v1 header in bytes.
const V1_PREFIX_LEN: usize = 5;
/// The maximum length of a v1 header in bytes.
const V1_MAX_LENGTH: usize = 107;
/// The terminator bytes of a v1 header.
const V1_TERMINATOR: &[u8] = b"\r\n";
/// The prefix length of a v2 header in bytes.
const V2_PREFIX_LEN: usize = 12;
/// The minimum length of a v2 header in bytes.
const V2_MINIMUM_LEN: usize = 16;
/// The index of the start of the big-endian u16 length in the v2 header.
const V2_LENGTH_INDEX: usize = 14;
/// The length of the read buffer used to read the PROXY protocol header.
const READ_BUFFER_LEN: usize = 512;

pub async fn read_proxy_header<I>(mut stream: I) -> Result<(I, Option<SocketAddr>), io::Error>
where
    I: AsyncRead + Unpin,
{
    // Mutable buffer for storing stream data
    let mut buffer = [0; READ_BUFFER_LEN];
    // Dynamic in case v2 header is too long
    let mut dynamic_buffer = None;

    // Read prefix to check for v1, v2, or kill
    stream.read_exact(&mut buffer[..V1_PREFIX_LEN]).await?;

    if &buffer[..V1_PREFIX_LEN] == v1::PROTOCOL_PREFIX.as_bytes() {
        read_v1_header(&mut stream, &mut buffer).await?;
    } else {
        stream
            .read_exact(&mut buffer[V1_PREFIX_LEN..V2_MINIMUM_LEN])
            .await?;
        if &buffer[..V2_PREFIX_LEN] == v2::PROTOCOL_PREFIX {
            dynamic_buffer = read_v2_header(&mut stream, &mut buffer).await?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No valid Proxy Protocol header detected",
            ));
        }
    }

    // Choose which buffer to parse
    let buffer = dynamic_buffer.as_deref().unwrap_or(&buffer[..]);

    // Parse the header
    let header = HeaderResult::parse(buffer);
    match header {
        HeaderResult::V1(Ok(header)) => {
            let client_address = match header.addresses {
                v1::Addresses::Tcp4(ip) => {
                    SocketAddr::new(IpAddr::V4(ip.source_address), ip.source_port)
                }
                v1::Addresses::Tcp6(ip) => {
                    SocketAddr::new(IpAddr::V6(ip.source_address), ip.source_port)
                }
                v1::Addresses::Unknown => {
                    // Return client address as `None` so that "unknown" is used in the http header
                    return Ok((stream, None));
                }
            };

            Ok((stream, Some(client_address)))
        }
        HeaderResult::V2(Ok(header)) => {
            let client_address = match header.addresses {
                v2::Addresses::IPv4(ip) => {
                    SocketAddr::new(IpAddr::V4(ip.source_address), ip.source_port)
                }
                v2::Addresses::IPv6(ip) => {
                    SocketAddr::new(IpAddr::V6(ip.source_address), ip.source_port)
                }
                v2::Addresses::Unix(unix) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Unix socket addresses are not supported. Addresses: {:?}",
                            unix
                        ),
                    ));
                }
                v2::Addresses::Unspecified => {
                    // Return client address as `None` so that "unknown" is used in the http header
                    return Ok((stream, None));
                }
            };

            Ok((stream, Some(client_address)))
        }
        HeaderResult::V1(Err(_error)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No valid V1 Proxy Protocol header received",
        )),
        HeaderResult::V2(Err(_error)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No valid V2 Proxy Protocol header received",
        )),
    }
}

async fn read_v2_header<I>(
    mut stream: I,
    buffer: &mut [u8; READ_BUFFER_LEN],
) -> Result<Option<Vec<u8>>, io::Error>
where
    I: AsyncRead + Unpin,
{
    let length =
        u16::from_be_bytes([buffer[V2_LENGTH_INDEX], buffer[V2_LENGTH_INDEX + 1]]) as usize;
    let full_length = V2_MINIMUM_LEN + length;

    // Switch to dynamic buffer if header is too long; v2 has no maximum length
    if full_length > READ_BUFFER_LEN {
        let mut dynamic_buffer = Vec::with_capacity(full_length);
        dynamic_buffer.extend_from_slice(&buffer[..V2_MINIMUM_LEN]);

        // Read the remaining header length
        stream
            .read_exact(&mut dynamic_buffer[V2_MINIMUM_LEN..full_length])
            .await?;

        Ok(Some(dynamic_buffer))
    } else {
        // Read the remaining header length
        stream
            .read_exact(&mut buffer[V2_MINIMUM_LEN..full_length])
            .await?;

        Ok(None)
    }
}

async fn read_v1_header<I>(
    mut stream: I,
    buffer: &mut [u8; READ_BUFFER_LEN],
) -> Result<(), io::Error>
where
    I: AsyncRead + Unpin,
{
    // read one byte at a time until terminator found
    let mut end_found = false;
    for i in V1_PREFIX_LEN..V1_MAX_LENGTH {
        buffer[i] = stream.read_u8().await?;

        if [buffer[i - 1], buffer[i]] == V1_TERMINATOR {
            end_found = true;
            break;
        }
    }
    if !end_found {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No valid Proxy Protocol header detected",
        ));
    }

    Ok(())
}
