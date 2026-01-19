use anyhow::{bail, Context, Result};
use common::encoding::encode_utf16le;
use hex::ToHex;
use log::{debug, info};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::crypto::aws_lc_rs::{default_provider, ALL_CIPHER_SUITES};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig, ALL_VERSIONS};
use x509_parser::oid_registry::OidRegistry;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::sldc;

/// Load certificates contained inside a PEM file
pub fn load_certs(filename: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);

    debug!("Loaded certificate {:?}", filename);

    let mut certs = Vec::new();
    for cert_res in rustls_pemfile::certs(&mut reader) {
        match cert_res {
            Ok(cert) => certs.push(cert.clone()),
            Err(error) => return Err(anyhow::anyhow!(error)),
        }
    }
    Ok(certs)
}

/// Load private key contained inside a file
pub fn load_priv_key(filename: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = fs::File::open(filename).context("Cannot open private key file")?;
    let mut reader = BufReader::new(keyfile);

    debug!("Loading private key {:?}", filename);

    loop {
        match rustls_pemfile::read_one(&mut reader).context("Cannot parse private key file")? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => break,
            _ => {}
        }
    }

    bail!(
        "No keys found in {:?} (encrypted keys not supported)",
        filename
    )
}

/// Certificate thumbprint = SHA-1 of entire certificate, as a hexadecimal string
pub fn compute_thumbprint(cert_content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(cert_content);
    let shasum_it = hasher.finalize();

    shasum_it.encode_hex::<String>()
}

pub struct TlsConfig {
    pub server: Arc<ServerConfig>,
    pub thumbprint: String,
}

/// Create configuration for TLS connection
pub fn make_config(args: &common::settings::Tls) -> Result<TlsConfig> {
    let cert =
        load_certs(args.server_certificate()).context("Could not load server certificate")?;
    let priv_key =
        load_priv_key(args.server_private_key()).context("Could not load private key")?;
    let ca_certs = load_certs(args.ca_certificate()).context("Could not load CA certificate")?;

    let ca_cert_content: &[u8] = ca_certs
        .first()
        .context("CA certificate should contain at least one certificate")?
        .as_ref();
    let thumbprint = compute_thumbprint(ca_cert_content);

    debug!("CA Thumbprint from certificate : {}", thumbprint);

    let mut client_auth_roots = RootCertStore::empty();

    // Put all certificates from given CA certificate file into certificate store
    for root in ca_certs {
        client_auth_roots
            .add(root)
            .context("Could not add certificate to root of trust")?;
    }

    // create verifier : does not allow unauthenticated clients
    // and authenticated clients must be certified by one of the listed CAs
    let client_cert_verifier =
        WebPkiClientVerifier::builder(Arc::new(client_auth_roots)).build()?;

    // Allow everything available in rustls for maximum support
    let mut crypto_provider = default_provider();
    crypto_provider.cipher_suites = ALL_CIPHER_SUITES.to_vec();
    // make config
    let mut config: ServerConfig = ServerConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_protocol_versions(ALL_VERSIONS)
        .context("Could not build configuration defaults")?
        .with_client_cert_verifier(client_cert_verifier) // add verifier
        .with_single_cert(cert, priv_key) // add server vertification
        .context("Bad configuration certificate or key")?;

    // any http version is ok
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    info!(
        "Loaded TLS configuration with server certificate {}",
        args.server_certificate()
    );

    Ok(TlsConfig {
        server: Arc::new(config),
        thumbprint,
    })
}

/// Get machine name from certificate
pub fn subject_from_cert(cert: &[u8]) -> Result<String> {
    // load certificate to decompose its content
    let cert = X509Certificate::from_der(cert)?.1;

    let oid_registry = OidRegistry::default().with_x509(); // registry of OIDs we will need
    let rdn_iter = cert.subject.iter_rdn(); // iterator on RDNs

    for subject_attribute in rdn_iter {
        // Each entry contains a list of AttributeTypeAndValue objects,
        // so we fetch their attribute type (= the OID representing each of them)
        let sn = subject_attribute.iter();

        for set in sn {
            // OID of the sub-entry
            let typ = set.attr_type();

            // get the SN corresponding to the OID (None if it does not exist)
            let oid_reg = oid_registry.get(typ).map(|oid| oid.sn());

            // the value we are interested in is only contained where the commonName is
            if oid_reg == Some("commonName") {
                // get data as text => FQDN of the client
                if let Ok(name) = set.as_str() {
                    return Ok(name.to_string());
                } else {
                    bail!("CommonName is empty")
                }
            }
        }
    }
    bail!("CommonName not found")
}

pub fn issuer_from_cert(cert: &[u8]) -> Result<String> {
    // load certificate to decompose its content
    let cert = X509Certificate::from_der(cert)?.1;

    let oid_registry = OidRegistry::default().with_x509(); // registry of OIDs we will need
    let rdn_iter = cert.issuer.iter_rdn(); // iterator on RDNs

    for subject_attribute in rdn_iter {
        // Each entry contains a list of AttributeTypeAndValue objects,
        // so we fetch their attribute type (= the OID representing each of them)
        let sn = subject_attribute.iter();

        for set in sn {
            // OID of the sub-entry
            let typ = set.attr_type();

            // get the SN corresponding to the OID (None if it does not exist)
            let oid_reg = oid_registry.get(typ).map(|oid| oid.sn());

            // the value we are interested in is only contained where the commonName is
            if oid_reg == Some("commonName") {
                // get data as text => FQDN of the client
                if let Ok(name) = set.as_str() {
                    return Ok(name.to_string());
                } else {
                    bail!("CommonName is empty")
                }
            }
        }
    }
    bail!("CommonName not found")
}

pub fn find_matching_ca(
    peer_certs: &[CertificateDer],
    ca_thumbprints: &HashMap<String, String>,
) -> Result<String> {
    peer_certs
        .iter()
        .find_map(|cert| {
            let issuer = issuer_from_cert(cert.as_ref()).ok()?;
            debug!("Checking issuer '{}'", &issuer);

            ca_thumbprints.get(&issuer).map(|ca_entry| {
                debug!("Found matching CA for issuer '{}'", &issuer);
                ca_entry.clone()
            })
        })
        .context("No trusted CA found in certificate chain")
}

/// Read and decode request payload
pub async fn get_request_payload(
    parts: hyper::http::request::Parts,
    data: hyper::body::Bytes,
) -> Result<Option<Vec<u8>>> {
    let payload = data.to_vec();

    let message = match parts.headers.get("Content-Encoding") {
        Some(value) if value == "SLDC" => {
            // Decompression is a blocking operation which can take a few milliseconds
            tokio::task::spawn_blocking(move || sldc::decompress(&payload).unwrap_or(payload))
                .await?
        }
        None => payload,
        value => bail!("Unsupported Content-Encoding {:?}", value),
    };

    Ok(Some(message))
}

/// Encode payload for response
pub async fn get_response_payload(payload: String) -> Result<Vec<u8>> {
    // If the payload to encode is large, encoding takes time and should be run
    // in a bocking task
    if payload.len() > 1000 {
        tokio::task::spawn_blocking(move || {
            encode_utf16le(payload).context("Failed to encode payload in utf16le")
        })
        .await?
    } else {
        encode_utf16le(payload).context("Failed to encode payload in utf16le")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[test]
    /// Test thumprint computation
    fn test_thumbprint() {
        let cert = b"0\x82\x02\xb50\x82\x02;\xa0\x03\x02\x01\x02\x02\x14g\x0c\x8d\xf7\t*\xb9\x04\x9b\xb2\x13\xf0H\xe9\x9a\x0fW5\xb0\x050\n\x06\x08*\x86H\xce=\x04\x03\x020W1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230825080210Z\x17\r230924080210Z0W1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\0\"\x03b\0\x04\xd8(@\xad\x9c\xa3\xe3\xb3\x14_\x8a-\xa3\x0fz\xbc_7|\x9cac\xc4`\x8f\xff\x0e\xe9\xadj:\x7fP\xdb\xf3\xb3\xdb$\xb5\xd9\xf4Xo\xae\xfa\xadlD\xdc+x\xf7s=\xbdi\x11\xc4u\0@\xdf\xc2\x86\xdb\xbe\xc4\x1f\x9bcc\xe8\xacnI\xe68\xa5vI\x9b\x99\xab\xc4\xa8\x10s\xe7\xcb\x7f\xa9\xc4\xf0\xc4\x97\x0b\xa3\x81\xc70\x81\xc40\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xfcL\x81rZ\x85\xd8\x1bI\xe4\xc3\xa7\x8bR\x1e\xb3\x19\xa9\xc4\x170\x81\x94\x06\x03U\x1d#\x04\x81\x8c0\x81\x89\x80\x14\xfcL\x81rZ\x85\xd8\x1bI\xe4\xc3\xa7\x8bR\x1e\xb3\x19\xa9\xc4\x17\xa1[\xa4Y0W1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14g\x0c\x8d\xf7\t*\xb9\x04\x9b\xb2\x13\xf0H\xe9\x9a\x0fW5\xb0\x050\x0c\x06\x03U\x1d\x13\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03h\00e\x021\0\x85)\xf7F\x88\xb5b\xdc&8\xfd\xae\xbe}\xd5Y\x83\x1ft\xe6\xf6\xdb!\xfco\x13\x17\xf0YM\\\xbb\x9c\xff\x12\xa2)\xc8\xc3\xb1u\x9eW,*1\xe2h\x020\x16\xe2|\xe0\x1cPJ\xde\x9d\"\xfa\xc3\ty\x06\x04\xf7\xe67z\x93\xa6tp9\xde\xa2\xee\xcfM\x95\x02DQzx$g\xc9\xf0\xaf\xf7;Vk\xef\xad{";
        let thumbprint = crate::tls::compute_thumbprint(cert).to_uppercase();
        assert_eq!(thumbprint, "6A4720A83504B818C86BAC099D3A4BEDE89945D9");

        let cert = b"0\x82\x02\xde0\x82\x02c\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020W1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230825080339Z\x17\r260614080339Z0`1\x180\x16\x06\x03U\x04\x03\x13\x0fWIN-KD7H02SOMLJ1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\0\"\x03b\0\x04W\x1d\xca\xf7};\x1a\x9c1\xbe\x11\x81\x05B0\xc7%6^\xa9\xb9\x90\xcb\x94\xfc^\x9c\xd2\x0c\xb2{\xac\x1b]-\xcd\xb2\x90\x0fnW\t@8\x7f#\x9fM\xa6\x17\x12\xfc$\xa1w\xdb0\xf6\xb8\xa6[\xf9\x8b\xfa\xa5\xfda\xde\xa9\x82\xd1\xd9\xbc\xb2\xac\xfb\x96mX\xe7\x16;v\xbclf8\xfe)\xa2\x06\xba\x81~\xa4\xa7\xa3\x81\xf90\x81\xf60\t\x06\x03U\x1d\x13\x04\x020\00\x11\x06\t`\x86H\x01\x86\xf8B\x01\x01\x04\x04\x03\x02\x07\x800\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14uq\x8d+\xda\xd0\xb9\x9aA\xb3\xe4+ S\x06\x84\x05\xdc\xa1q0\x81\x94\x06\x03U\x1d#\x04\x81\x8c0\x81\x89\x80\x14\xfcL\x81rZ\x85\xd8\x1bI\xe4\xc3\xa7\x8bR\x1e\xb3\x19\xa9\xc4\x17\xa1[\xa4Y0W1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14g\x0c\x8d\xf7\t*\xb9\x04\x9b\xb2\x13\xf0H\xe9\x9a\x0fW5\xb0\x050\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x05\xa00\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x020\n\x06\x08*\x86H\xce=\x04\x03\x02\x03i\00f\x021\0\x94;\xa2s\x9czu\x9d$\xee\xe6:[\xfa+Y\xbaF\x01\xb2n\x12\x01\xb3F>\xe5\xf9B\xff\xa1\x96\xa7*\xe2\xf9\x01q\x8a\xc3k\xfc\xb3'\xba\x89\xe3\xdd\x021\0\xc9KU\xde\xb2\xe4\xcd[\x08c\x04*;\x93\x0bw\xeck\x94\xe41\xa6 M\xf0\xa7\xd4l\x04\x84\xc1\x80W\xb9\xcf\xb6BN\xe4\xcb\xa3\xc25\xd9\xcb1\x14\xcd";
        let thumbprint = crate::tls::compute_thumbprint(cert).to_uppercase();
        assert_eq!(thumbprint, "EAE93EA8A4CC386849A873D3B9E5EE57886A1603");
    }

    #[test]
    /// Test retrieving subject name from certificate
    fn test_get_subject_from_cert() {
        use super::*;

        // Non-empty subject
        let certificate = b"0\x82\x02\xae0\x82\x025\xa0\x03\x02\x01\x02\x02\x14qX\xbd\x8c\\\xbb\xa7y\xbd\x13\xf3\xcb\xb1f}\xc3\xca!\xdf\x9f0\n\x06\x08*\x86H\xce=\x04\x03\x020U1\r0\x0b\x06\x03U\x04\x03\x13\x04subj1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230828081803Z\x17\r230927081803Z0U1\r0\x0b\x06\x03U\x04\x03\x13\x04subj1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\0\"\x03b\0\x04\xd4\xf3G\xdeMT\xd1\x8d\x9bf\xb5m\xe4[%\xa7\xe7\xc6\xc2\xdd}\xef\x826\x95|gT\x8a\xcb\xbetP\xb7\x98\xd4St\x1ex%\x7fD\xf3\x0f|\x1c\xf6\xa5\xa6(\xc5\x9f\xbaJz8AV\xa9\x03&\xf8\x02\xa3\xf8\xd9#\x83\xe3\x0e\xd9;^\x87\xf6\xb0\xdc\x98\xc7Y\x15w\x18\x10\xbc\x11\xca\x08\x0c\xa2\x10\xfa\xa3\xf1X\xa3\x81\xc50\x81\xc20\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xbe\xce\x1f\xb7\xad\xe7\x8d\x07\xb5\xe6\xb2\xa1\xfd\xf5Z\xd0?\x0ey`0\x81\x92\x06\x03U\x1d#\x04\x81\x8a0\x81\x87\x80\x14\xbe\xce\x1f\xb7\xad\xe7\x8d\x07\xb5\xe6\xb2\xa1\xfd\xf5Z\xd0?\x0ey`\xa1Y\xa4W0U1\r0\x0b\x06\x03U\x04\x03\x13\x04subj1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14qX\xbd\x8c\\\xbb\xa7y\xbd\x13\xf3\xcb\xb1f}\xc3\xca!\xdf\x9f0\x0c\x06\x03U\x1d\x13\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03g\00d\x020Gn\xb7F\xf9\x06<\xf6\x19\xc0\xdaX\xa6\xf2\x19\x04h\x1bB\x0fIx\xfa\x18{\x80\x94$B\x93\xe9T\x91\xa7\xb53\xb6\xfa-\xe2\x17\xbb\x86PZJ\x98\x93\x020\x08}-\xa7b\x04~\xaa?\xc6\xe5\xec9k'\x8b\xc5\xa2\x15\x1c\x8b\xfb6w4\xf2\xceY<\x8f\t\xd1\xc3\x93l\xc6\x9d\x98\x8eBN>#6\xe9\xf8\x91\xbe";
        let subject = "subj";
        assert_eq!(subject, subject_from_cert(certificate).unwrap());

        // Other type of private key
        let certificate = b"0\x82\x04&0\x82\x03\x0e\xa0\x03\x02\x01\x02\x02\x01\x010\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\00Z1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x170\x15\x06\x03U\x04\n\x13\x0eca.stage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230811075732Z\x17\r260531075732Z0T1\x0c0\n\x06\x03U\x04\x03\x13\x03win1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\0\x03\x82\x01\x0f\00\x82\x01\n\x02\x82\x01\x01\0\xf3\xed\x9a\x9f\xb0\xbd\x8a\xe3\x86\xa9\xe2)8\x1a\xb4[\r\xb3[\xf3\x81$\x83\xd1\xa8\x15\xe2\xe9\xf8\x8d\xd8\xcbH\xd5\xd0m\x8b-\xdd\xf8\xd2\xa1\xd8$\x11c&\x1fd\x81\xa6\xd4\x10=8\x17X\xa9\xfe\x06\xda*)x\x91y\xb9ZS\xea\x90\x17\xe2\xfdyYL\x8e\xc2\xdf\xe6\xfd\x0e\x11\xdat0\x08\x14\xc3\x91\xb4\x15$)#T)\xa1\x9cG|\x8e]Z\x08\xc6\xb0\x1c\x7f\xfd\xe7\xac\xbc\xba\xb6\x8am\xfc}1W\x0e\x95\x91\xc4p\xf5\x99F\x191\xdcB\xd0\xf3H\xcf>6\x9eR\xfc\xef=\x80\xe2\xaa\x18\xe2\x14\x9f5\xfe\0=\0\xd36\xcc\xe4\n\x0e\xc7%M\xe4X[XP\xe3\xf6\xd4~\x89\x1eC\x90\xc1\xa1\xa6\xb7oZ\x04l\xb2A\xf5\x94!&\xf1\xaf\xc0q\xc9F\xf8L\x8c1\xee\x84\x85>\xf4\xea\xcf\xf4\x1fp<\x83\xcb\xb0\x98\x18\xe84d\xf9\x90\xa2\xae\xd2X\x85\x94fS\x96\x03b\xd6\x83Y\xcf\xae\xc1\x90\x06\x80\xc4\x0e\xcf\x9f\xa9T\xf7\x15\x945y1\x02\x03\x01\0\x01\xa3\x81\xfc0\x81\xf90\t\x06\x03U\x1d\x13\x04\x020\00\x11\x06\t`\x86H\x01\x86\xf8B\x01\x01\x04\x04\x03\x02\x07\x800\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xd0\xe3W\xae\x93\xd2_\xc8o\xb0\xbb\xc9\xe7\x9fH\xa6\xeaU#\x0f0\x81\x97\x06\x03U\x1d#\x04\x81\x8f0\x81\x8c\x80\x14M\xf0-M\xaa\x02\xab\xc7\xa5\xc4\xed\xb2\xcc\xf5H\x7fC\xaeZ\xf7\xa1^\xa4\\0Z1\x0f0\r\x06\x03U\x04\x03\x13\x06WEF-CA1\x170\x15\x06\x03U\x04\n\x13\x0eca.stage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14\r\x08\xc4\xe1\xea)\x1f\xe0\n\x80\xcf\x8a\x9c.:)y7\xc1\xff0\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x05\xa00\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x020\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\0\x03\x82\x01\x01\0\x8b\xb8I<b`t8\xdf\xa1\xd6\xf9\xaat\x98:\xf7\x9b.\x9e\xb7W\xac\x9cYG\x8b\xcb\xe1\xdc\xf2\xddV'\xd9|\x9c\xb2&\\\x03{\x8b\x1e\xa9UCZu\xd5\x98\x0c\xec!-\xb84s\xb7\xdf\xb8\xe3\xf0x=\x80\xcf\xef-';fP\xe7\\a\xab\x01\xe8Ys\xddp\x9ao\x11\xb8&\x99\xb8\xbf(\x15\x87\x99:\x13)\xf0\x14\x1f\xde\x0eH\x16K6\x8b\xaf\x0f\xc6yE\xdbV\xd94\x1a\xde\x93\xe9t\xe5fF\xb10\x1bt\x8fq\x8a\xeb\x02\xad\xbc\x13lP\0\xe8AD\xb5\xc7\x16\x0f|aK\xe7\xf7\xb33nHN\x7f\x95+\xa8\xc2\xe3+\xe1\x9d\xd6B{\xdf\xb2\x97\xa9\x05P\xeb=0K;\xf7\x16\x06lIK}8O\xd2\x0fC\x9f\x8c\x8a\xc3\x05\xb8\x97^\x7f\xe6\xc8(\x1c \xdeg2\x998H3\x01\x97q\x95\xc2\x06\x86-\x11\x9cC\x01y\xc3v\x86H\x0cR@q\x19r\xfe@\xb7\xe39`\xe172\x7f\xd0\x0f\xa6\xdb\x074#\x8a\xfa\xde";
        let subject = "win";
        assert_eq!(subject, subject_from_cert(certificate).unwrap());

        // Other content
        let certificate = b"0\x82\x03:0\x82\x02\xc0\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020F1\x140\x12\x06\x03U\x04\n\x0c\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05state1\x110\x0f\x06\x03U\x04\x07\x0c\x08location0\x1e\x17\r230829085610Z\x17\r260618085610Z031\x0e0\x0c\x06\x03U\x04\x03\x13\x05aaaaa1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\0\x03\x82\x01\x0f\00\x82\x01\n\x02\x82\x01\x01\0\xa2\x85W\x8b\xf4\xe4\xb91 \xd5I\x0f\xf6\xf9;\xe6\x04\x9cSen/G\xf7(\xcd\xf6Nj\x0b\xef\x1f=\xef\xcb1\xd8\x83\xbd\x12\x97f\xc1\xd7\xa5\xc84o\x08\xb3\xeb\n\xa0\x80h\xb2p\x1e.y\xfd\xec\xa1cc\xd6c\xf7\x18\xb5aT\xce\xba\x11x0\xbe\xc7O|Uf\x81\x13\x8e;\x8b\xb6\x14TV\x94_\x05\x88!\xec@\xc1R9 \x8d\x9b{PW\x07<*}\xfc\xf7\xd0\xaf\x02T7\x075\xc8\xc1\x95\x8b\x93\x88\x1d\xb5b\x17\x03a5\xbfK\x1b\xdaH\x0c\xe2Z\xd8*w\xe3\x04\x01&P\xa6\x1d0u\"dR\x8e%\xa0h\xa9\xbf\x07\xa2\xda5\xe8c\xac\x9fL\xc9\x18\xc5\x03\xbf\xe3=\x0bs\xb8\xb3+\xd6Y\x9eh\xd1\xbd\x15s[\xd1\xee(f\xc8\x0b8\x0f\xd6l\x8fng\x8c*\xed\x12\xfb\xe39\xfeMV\x7f\n\x16\x8a\x95#v\xeey\xf5#\r\x17\xe8z\x95+\xb17=w7f]\xefX\x03\xd4\x11\x07\xfffWL\x02%\x11\x93)\xa1\x02\x03\x01\0\x01\xa3\x81\xe60\x81\xe30\t\x06\x03U\x1d\x13\x04\x020\00\x11\x06\t`\x86H\x01\x86\xf8B\x01\x01\x04\x04\x03\x02\x06@0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xcbT\xeb\xe5\xf9>E\xb8\x98)\x9e\r\xdc\xe1\xba\xca\xb5 -\xc50\x81\x81\x06\x03U\x1d#\x04z0x\x80\x14\xbe\xce\x1f\xb7\xad\xe7\x8d\x07\xb5\xe6\xb2\xa1\xfd\xf5Z\xd0?\x0ey`\xa1J\xa4H0F1\x140\x12\x06\x03U\x04\n\x0c\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05state1\x110\x0f\x06\x03U\x04\x07\x0c\x08location\x82\x14\x13\ti\x0b\x0b\x95~\xe1X\x03\x99V3\x95\xceruHOx0\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x05\xa00\x13\x06\x03U\x1d%\x04\x0c0\n\x06\x08+\x06\x01\x05\x05\x07\x03\x010\n\x06\x08*\x86H\xce=\x04\x03\x02\x03h\00e\x021\0\xd2\xad\xa3\x01\xc6\xee\xc80\"\x81\x14\xb7?A\xd9\xae\n\xe5`pne\xdd\x9b\xbc\xfevfO\xf6\x8e\x92i\xe2\x99\xa4s\x07r\xb4r\x13\xaeZ\nJ\xf6q\x020!\xf6\xc3\xe8\xec\xd6Z\xe90b\x08\xa3\x8c\xc2~\xb0y\xe2\xe1?V\x99\x87H\x96Q|\x14\x17\x14\x14x)}\xa3$z\xc7\xff\xbe\x080#?\x06\x85L4";
        let subject = "aaaaa";
        assert_eq!(subject, subject_from_cert(certificate).unwrap());

        // CA
        let certificate = b"0\x82\x04\x100\x82\x02\xf8\xa0\x03\x02\x01\x02\x02\x14~\xa1W\x8c\xb4\\\xe9S\x80\xa3\xb4\xce\xc2\xaa\xa3yg\xb9:u0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\00[1\x130\x11\x06\x03U\x04\x03\x13\nca-machine1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230829090243Z\x17\r230928090243Z0[1\x130\x11\x06\x03U\x04\x03\x13\nca-machine1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x82\x01\"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\0\x03\x82\x01\x0f\00\x82\x01\n\x02\x82\x01\x01\0\xb8\xe1\xb4\xd6\xa1\xe5\x1a\x0b3\xc5\xb2_\x04\x0f\xd7\x18\xb1d'\\\xa9X\xc8\xef\x9d72\xf7+\x0b\xed\xe4ik\xf4\x8e\x9a\x8a\xf5\xa8\xe1\x18>\xd1\xd6\xd3\xb0\xeb\xf2y\xaf\xdc\xb3\x04%\x87\xc7\xb7\xa5\x12\x1f\xcd\xa1=D\xc8x9\x03\xab``\xf79MO\xea\x15\xb0`Z\x96\x10\xb7\xb1\x99\xb1\xf9\xdd\x03q+\xf0\x16\x914\xda\xbcH\xa8\xa0j\xc2\xdeE\xe6iO\x9c\x07}x.\xfa\x91\x0c\xdb\xb0\xfcF\xe3\xd4m_\x03~\xbe\xd4[\xe2[\xa8\xa6\x99zZ\xdb\x9c\xa6\xa1\x04\x89\xe4\xd5\x99\xb7\xcd\xfb\xe5\xbcB\x13\x19\x87c\xb5\x11\x0bW\x8c\xf2\x83;|\"nq\x89\x17uU\xbaZX=\xbc\x99\xf5\xfc: \x0c\xf9\xc8\x11\x8d\xf0&\x82.L\xbe\xf7\xfe\xf3\xad\t\xfa\xfb\xc5\x1d\x81m\x93\xae<\x12\xb0\xc63\xba\xd2\xc5\xb0(\x06\x15X2\xc6\xeaS\xe9\xb4{\xf4:\xe0!\xea\xe1-K[I^\xe7\xa1a\x9f5$\x1fN\xd9\xa6ZX\xbe\x90\xed\xb9\x0f0\x89e\x02\x03\x01\0\x01\xa3\x81\xcb0\x81\xc80\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xd1k\x12/\xa1~\xe2I9C\x1d|\xb7\xcf\x8a\xf75\xe8\x02q0\x81\x98\x06\x03U\x1d#\x04\x81\x900\x81\x8d\x80\x14\xd1k\x12/\xa1~\xe2I9C\x1d|\xb7\xcf\x8a\xf75\xe8\x02q\xa1_\xa4]0[1\x130\x11\x06\x03U\x04\x03\x13\nca-machine1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14~\xa1W\x8c\xb4\\\xe9S\x80\xa3\xb4\xce\xc2\xaa\xa3yg\xb9:u0\x0c\x06\x03U\x1d\x13\x04\x050\x03\x01\x01\xff0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\0\x03\x82\x01\x01\0O\x16\x9f\x97\x1dZ\x82^\xb2\xaa\xd0\xd7mAF\x12\xcaC\xfd2_\xfd\x91\xfc\xe9\xfceG\xdb\xf8d\xdfc\xef\x9c\xfa\x84BI\x18\x19\x99\x19\xe2\xde\xaf\xdf\xad\xbc_\x16\xcd\xa4;\xd5'\xdbk\x15\0g\xd3\xd9\x9fs\xd4\xc6\xdf\t9\x07Z\x102\x80\x1fC\xd96;\x89\xe9\x05\xd7\x93T(*\xd5\x99\xaeR\xe4C\xdd\x89\x1f\x91\xaf\x95\xd3\x82l\xd3V\xdc\\:g\xc8\xe7`\xbcZo\xbe\xd8\xd3y\x1f\x82\xe2\xe8\x94\xcc\xa7KYg\xdb\xa1\xbc\x08\xfd\xd9+\xbaq\xb7-}\xf9k\x01_\xe2\x8a\xc4\x8d\xfad\xcf\xf4\x0c\xce\xa4\xff\x90K\x88{\x7fK\xacT\x85\xf7t\x18\xb4\x02 \xe5\xf7bK\x85\xc7|\xdb\xe1\x14\xd1\xba9=P\xf5M\xe1LOz\xa8i\xf1\x85\xc6\x108\xc9\xc8g\x7fk\xf5\xff|\xc9j\n\x92\x0c\\\xe1\xa7\xdf\xc5\x1c\xda\xcf\xe4\xda\x96#\xa5\xa79S\xd3&3\x85\xbaU \x8a\x8d\xb1\xe4*;\x9a\xddSuj6\xe1\xcab\xf8a\xf64d";
        let subject = "ca-machine";
        assert_eq!(subject, subject_from_cert(certificate).unwrap());
    }

    #[test]
    #[should_panic(expected = "CommonName")] // XXX : panics not as we thought but still panics
    /// Test retrieving subject name from certificate
    fn test_get_subject_empty() {
        use super::*;

        // Empty subject
        let certificate = b"0\x82\x02\x1e0\x82\x01\xa4\xa0\x03\x02\x01\x02\x02\x14\x13\ti\x0b\x0b\x95~\xe1X\x03\x99V3\x95\xceruHOx0\n\x06\x08*\x86H\xce=\x04\x03\x020F1\x140\x12\x06\x03U\x04\n\x0c\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05state1\x110\x0f\x06\x03U\x04\x07\x0c\x08location0\x1e\x17\r230828084524Z\x17\r230927084524Z0F1\x140\x12\x06\x03U\x04\n\x0c\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x0c\x05state1\x110\x0f\x06\x03U\x04\x07\x0c\x08location0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\0\"\x03b\0\x04\xd4\xf3G\xdeMT\xd1\x8d\x9bf\xb5m\xe4[%\xa7\xe7\xc6\xc2\xdd}\xef\x826\x95|gT\x8a\xcb\xbetP\xb7\x98\xd4St\x1ex%\x7fD\xf3\x0f|\x1c\xf6\xa5\xa6(\xc5\x9f\xbaJz8AV\xa9\x03&\xf8\x02\xa3\xf8\xd9#\x83\xe3\x0e\xd9;^\x87\xf6\xb0\xdc\x98\xc7Y\x15w\x18\x10\xbc\x11\xca\x08\x0c\xa2\x10\xfa\xa3\xf1X\xa3S0Q0\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xbe\xce\x1f\xb7\xad\xe7\x8d\x07\xb5\xe6\xb2\xa1\xfd\xf5Z\xd0?\x0ey`0\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xbe\xce\x1f\xb7\xad\xe7\x8d\x07\xb5\xe6\xb2\xa1\xfd\xf5Z\xd0?\x0ey`0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03h\00e\x021\0\xd54!\xddc\xb1\xa4\xf6S-Q_]\xa5\xe7\xd2\xf4B\x969R^\xcd\x9d\xa1\xa5\"\xf5\t1]c\x19\xeb)\xce\xc2jd\xf5#\x14t\x0e\x16\x8b_$\x020o\xe1\xd1\x94PC\x05\xb1<\xe3Ch\xd5\x19\x80\\gHH\xc5>d\xc5\x1a\x80\x18a\x82\xc4q\x94i\xa7\xd04$\x89\xdc\xfe\xc6Q\xe9\xdf`\xceM\xbd\xa9";
        subject_from_cert(certificate).unwrap();
    }

    #[test]
    #[should_panic(expected = "CommonName not found")]
    /// Test retrieving subject name from certificate
    fn test_get_no_subject() {
        use super::*;

        // No subject
        let certificate = b"0\x82\x02\x810\x82\x02\x06\xa0\x03\x02\x01\x02\x02\x14C\x1e\xffg{G\x9a\xa9ovZ'E\xd8\r\x1cds.\x900\n\x06\x08*\x86H\xce=\x04\x03\x020F1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0\x1e\x17\r230830084659Z\x17\r230929084659Z0F1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\0\"\x03b\0\x04\xed\x80@\x80!.`\x06\xcd\xae]&\xc0\x8c.87\xc2\x14\x9da\xe75\x8e\xbcET\xda\x93\x0bM\xa0\x19O7cyC/\xff\xf3\x81\x10\xe2o\xe44\x029XE\x0c\xaaa\x95n\xb6\xb7\xcf\x90\x05\x95\xdcDn \xad\x1f\xe5\xda\xf8\x0e|\08>4'W\xf1k`\x85\xdf\xff}<\x0c\x8d\xc0q.\x10&\xfa<\xa3\x81\xb40\x81\xb10\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x146\xcfC0\x06\x868%4\xd9\xad\\dV&\xec\x89z\xb0\xce0\x81\x81\x06\x03U\x1d#\x04z0x\x80\x146\xcfC0\x06\x868%4\xd9\xad\\dV&\xec\x89z\xb0\xce\xa1J\xa4H0F1\x140\x12\x06\x03U\x04\n\x13\x0bstage.local1\x0b0\t\x06\x03U\x04\x06\x13\x02FR1\x0e0\x0c\x06\x03U\x04\x08\x13\x05state1\x110\x0f\x06\x03U\x04\x07\x13\x08location\x82\x14C\x1e\xffg{G\x9a\xa9ovZ'E\xd8\r\x1cds.\x900\x0c\x06\x03U\x1d\x13\x04\x050\x03\x01\x01\xff0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03i\00f\x021\0\x9dY\x02N\x98\xacU\x92\x96\x0c\xe6\x9d\x9c\xb6\xc1\xf3\x1e\xb6\x8a]\xf5\xf9\x84\xb2p\xaa\x80\x80\xdd@\xa0nG\\\xf8\xb6\xb6P\r=\xd4\x95\xc7\xc4j\xed\xa8\x8a\x021\0\xefM8\x86?d\x8c\xbf\xf7\x8c\xdc\x97\xb0\xd1\xc3\x05\x88\xc7\xa8\x87?\xc1\xf8\xa98;N\xa1r\xb9,\xf0\x0c\xd1YZ\xf36{!\x8c\xa1\xe1gQ\xa4\x01\xca";
        subject_from_cert(certificate).unwrap();
    }

    #[test]
    #[should_panic(expected = "(encrypted keys not supported)")]
    /// Test trying to load private key from a file that contains none (for instance a certificate)
    fn test_load_private_key_no_keys() {
        use super::*;

        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.pop();
        path.push("tests/certs/no_key.pem");
        load_priv_key(&path.into_os_string().into_string().unwrap()).unwrap();
    }

    #[test]
    #[should_panic(expected = "Cannot parse private key file")]
    /// Test trying to load private key from a malformed file (for instance missing the '--- END KEY ---' line)
    fn test_load_private_key_wrong_format() {
        use super::*;

        // let mut file = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        // file.push_str("/../tests/certs/wrong_format.pem");
        // let _key = load_priv_key(&file);
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.pop();
        path.push("tests/certs/wrong_format.pem");
        load_priv_key(&path.into_os_string().into_string().unwrap()).unwrap();
    }

    #[test]
    /// Test loading proper private keys from files
    fn test_load_private_key() {
        use super::*;

        // content = base64 -d <<< "<key content only>" | hexdump   => list of integers, without final '0x00' if present

        // ecdsa
        // let mut file = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.pop();
        path.push("tests/certs/key_ecdsa.pem");
        let key = load_priv_key(&path.into_os_string().into_string().unwrap());
        // file.push_str("/../tests/certs/key_ecdsa.pem");
        // let key = load_priv_key(&path);
        let content = [
            48, 129, 164, 2, 1, 1, 4, 48, 187, 86, 151, 53, 184, 134, 70, 143, 168, 81, 239, 30,
            69, 203, 72, 236, 115, 154, 49, 20, 241, 27, 231, 109, 68, 27, 44, 190, 87, 125, 26,
            53, 211, 177, 30, 133, 50, 219, 198, 214, 162, 185, 145, 56, 34, 246, 96, 225, 160, 7,
            6, 5, 43, 129, 4, 0, 34, 161, 100, 3, 98, 0, 4, 212, 243, 71, 222, 77, 84, 209, 141,
            155, 102, 181, 109, 228, 91, 37, 167, 231, 198, 194, 221, 125, 239, 130, 54, 149, 124,
            103, 84, 138, 203, 190, 116, 80, 183, 152, 212, 83, 116, 30, 120, 37, 127, 68, 243, 15,
            124, 28, 246, 165, 166, 40, 197, 159, 186, 74, 122, 56, 65, 86, 169, 3, 38, 248, 2,
            163, 248, 217, 35, 131, 227, 14, 217, 59, 94, 135, 246, 176, 220, 152, 199, 89, 21,
            119, 24, 16, 188, 17, 202, 8, 12, 162, 16, 250, 163, 241, 88,
        ];
        assert_eq!(key.unwrap(), PrivateKeyDer::Sec1(content.to_vec().into()));

        // rsa
        // let mut file = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.pop();
        path.push("tests/certs/key_rsa.pem");
        let key = load_priv_key(&path.into_os_string().into_string().unwrap());
        // file.push_str("/../tests/certs/key_rsa.pem");
        // let key = load_priv_key(&path);
        let content = [
            48, 130, 4, 189, 2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4,
            130, 4, 167, 48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 208, 9, 205, 253, 201, 187,
            213, 10, 117, 191, 62, 81, 134, 149, 52, 173, 49, 12, 0, 71, 60, 5, 228, 179, 32, 90,
            14, 210, 195, 64, 177, 254, 103, 143, 136, 214, 113, 32, 49, 181, 45, 184, 163, 125,
            193, 193, 0, 239, 196, 45, 20, 129, 83, 88, 123, 89, 48, 18, 171, 121, 32, 212, 133,
            116, 208, 10, 194, 38, 103, 45, 47, 124, 151, 159, 131, 200, 55, 188, 47, 154, 64, 83,
            251, 251, 216, 255, 97, 178, 213, 205, 215, 104, 127, 119, 166, 131, 238, 245, 215, 63,
            30, 197, 72, 133, 230, 238, 162, 203, 246, 173, 215, 176, 48, 26, 143, 114, 105, 59,
            18, 215, 168, 76, 134, 113, 154, 28, 102, 140, 128, 127, 133, 160, 111, 124, 155, 24,
            104, 206, 145, 79, 98, 25, 37, 16, 49, 228, 27, 170, 5, 105, 198, 87, 43, 83, 79, 89,
            187, 182, 207, 196, 24, 114, 134, 89, 125, 90, 152, 154, 195, 152, 52, 14, 107, 96, 88,
            107, 33, 36, 236, 216, 56, 0, 122, 241, 129, 19, 59, 54, 103, 40, 209, 72, 211, 63,
            136, 64, 195, 207, 213, 146, 237, 124, 56, 30, 188, 132, 58, 231, 167, 102, 87, 219,
            167, 151, 29, 156, 249, 74, 215, 159, 185, 123, 99, 170, 246, 191, 239, 144, 19, 135,
            99, 92, 205, 37, 239, 173, 210, 163, 78, 83, 79, 146, 217, 160, 41, 212, 173, 147, 129,
            232, 112, 41, 6, 126, 84, 221, 2, 3, 1, 0, 1, 2, 130, 1, 0, 81, 20, 97, 42, 22, 35,
            148, 134, 61, 25, 201, 233, 240, 47, 218, 149, 221, 85, 182, 14, 13, 64, 166, 191, 129,
            78, 88, 20, 160, 112, 104, 110, 164, 97, 246, 140, 205, 14, 37, 17, 93, 190, 102, 73,
            174, 231, 207, 187, 162, 147, 135, 56, 88, 9, 86, 25, 142, 120, 216, 71, 159, 25, 244,
            225, 111, 235, 161, 123, 98, 30, 228, 49, 4, 206, 240, 135, 105, 225, 120, 20, 0, 26,
            59, 77, 14, 103, 137, 230, 47, 25, 200, 104, 59, 181, 160, 58, 47, 57, 181, 40, 46,
            143, 233, 17, 246, 204, 238, 185, 219, 108, 41, 113, 203, 109, 174, 150, 130, 152, 185,
            97, 63, 128, 131, 173, 102, 200, 198, 214, 43, 74, 69, 21, 38, 77, 110, 5, 98, 193,
            185, 124, 249, 97, 161, 89, 153, 30, 42, 243, 22, 136, 240, 213, 225, 58, 83, 131, 159,
            252, 105, 135, 234, 136, 216, 113, 35, 182, 1, 248, 191, 144, 176, 24, 115, 135, 85,
            155, 183, 221, 101, 199, 28, 4, 181, 230, 195, 105, 114, 81, 130, 38, 199, 170, 183,
            19, 52, 173, 54, 169, 78, 213, 162, 223, 66, 163, 13, 58, 56, 234, 220, 179, 202, 169,
            95, 253, 216, 188, 156, 178, 120, 145, 252, 162, 255, 112, 212, 32, 175, 146, 54, 130,
            8, 73, 141, 84, 71, 180, 50, 205, 225, 164, 11, 5, 204, 14, 105, 216, 77, 186, 103,
            246, 210, 68, 244, 252, 169, 233, 2, 129, 129, 0, 245, 159, 80, 103, 124, 221, 239,
            162, 237, 168, 180, 10, 81, 96, 79, 197, 207, 166, 136, 53, 127, 49, 147, 45, 229, 227,
            242, 148, 187, 205, 163, 91, 139, 14, 76, 61, 89, 195, 170, 154, 186, 162, 151, 29,
            145, 233, 69, 73, 13, 26, 5, 125, 78, 210, 70, 29, 243, 172, 30, 25, 105, 87, 29, 102,
            73, 111, 4, 169, 242, 65, 85, 50, 114, 219, 79, 170, 154, 34, 213, 30, 140, 189, 41,
            237, 4, 95, 190, 6, 212, 172, 16, 250, 16, 213, 186, 40, 7, 49, 112, 1, 242, 47, 160,
            137, 68, 23, 80, 110, 78, 185, 62, 239, 47, 227, 115, 220, 123, 58, 105, 32, 70, 228,
            190, 26, 38, 135, 126, 207, 2, 129, 129, 0, 216, 211, 249, 249, 89, 140, 21, 156, 123,
            76, 17, 133, 108, 36, 161, 76, 236, 193, 182, 246, 139, 69, 75, 186, 138, 43, 46, 52,
            91, 96, 176, 103, 120, 29, 158, 4, 52, 9, 13, 41, 198, 49, 156, 196, 223, 164, 42, 96,
            16, 98, 21, 183, 15, 202, 46, 55, 119, 48, 187, 179, 248, 5, 236, 60, 213, 227, 61, 42,
            86, 228, 189, 237, 71, 236, 185, 134, 50, 82, 231, 63, 127, 5, 142, 25, 47, 251, 166,
            154, 81, 115, 113, 243, 92, 221, 150, 140, 220, 209, 172, 104, 103, 107, 76, 31, 28,
            69, 183, 112, 41, 17, 83, 26, 243, 139, 247, 105, 137, 238, 174, 210, 243, 81, 217,
            171, 137, 136, 60, 147, 2, 129, 128, 19, 165, 108, 142, 250, 131, 221, 249, 16, 61, 96,
            57, 59, 13, 19, 20, 101, 105, 146, 151, 132, 214, 248, 72, 193, 140, 156, 8, 157, 132,
            243, 62, 13, 63, 85, 133, 202, 186, 69, 217, 30, 120, 134, 209, 204, 171, 245, 232,
            195, 237, 130, 230, 228, 249, 24, 182, 168, 152, 233, 199, 106, 143, 151, 64, 105, 59,
            66, 10, 61, 224, 79, 234, 59, 25, 163, 163, 167, 180, 133, 139, 110, 2, 107, 106, 19,
            225, 124, 151, 155, 71, 48, 12, 112, 112, 71, 245, 143, 173, 186, 161, 205, 55, 86, 5,
            228, 182, 96, 174, 146, 9, 107, 41, 66, 145, 84, 225, 27, 210, 46, 58, 112, 177, 55,
            43, 108, 77, 134, 45, 2, 129, 128, 33, 209, 190, 85, 164, 31, 243, 102, 250, 220, 60,
            135, 96, 252, 189, 163, 239, 241, 175, 5, 249, 103, 15, 142, 194, 234, 69, 68, 169, 84,
            5, 111, 190, 14, 112, 141, 27, 72, 166, 34, 243, 228, 221, 28, 223, 253, 13, 22, 250,
            183, 49, 199, 225, 208, 153, 48, 209, 136, 106, 94, 129, 186, 250, 195, 234, 96, 141,
            51, 195, 101, 222, 49, 218, 92, 19, 251, 216, 113, 145, 220, 23, 133, 216, 74, 25, 111,
            216, 230, 140, 249, 194, 182, 64, 175, 215, 65, 149, 87, 166, 218, 137, 246, 244, 98,
            141, 216, 89, 234, 70, 157, 139, 38, 211, 1, 235, 207, 44, 82, 108, 54, 62, 249, 111,
            72, 16, 37, 141, 189, 2, 129, 129, 0, 180, 17, 238, 19, 205, 160, 47, 8, 48, 75, 92,
            89, 210, 98, 132, 3, 108, 80, 209, 8, 225, 41, 79, 166, 226, 78, 35, 193, 4, 5, 32, 43,
            63, 148, 239, 69, 132, 107, 138, 65, 162, 162, 179, 100, 54, 92, 55, 3, 33, 104, 227,
            75, 201, 52, 134, 220, 88, 149, 189, 78, 68, 135, 180, 41, 237, 198, 230, 47, 44, 243,
            209, 93, 100, 146, 76, 57, 10, 59, 183, 24, 146, 242, 98, 177, 116, 7, 105, 163, 146,
            78, 251, 42, 139, 154, 212, 55, 81, 121, 95, 100, 162, 1, 37, 95, 68, 141, 203, 80,
            132, 223, 102, 86, 216, 5, 218, 125, 237, 212, 218, 133, 165, 97, 62, 73, 27, 106, 224,
            64,
        ];
        assert_eq!(key.unwrap(), PrivateKeyDer::Pkcs8(content.to_vec().into()));
    }
}
