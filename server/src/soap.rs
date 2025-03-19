use anyhow::{anyhow, bail, ensure, Context, Result};
use log::{debug, trace};
use quick_xml::events::{BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use roxmltree::{Document, Node};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use uuid::Uuid;
use xmlparser::XmlCharExt;

const SOAP_ENVELOPE_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
const MACHINE_ID_NS: &str = "http://schemas.microsoft.com/wbem/wsman/1/machineid";
const ADDRESSING_NS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const WSMAN_NS: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
const MS_WSMAN_NS: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
const SUBSCRIPTION_NS: &str = "http://schemas.microsoft.com/wbem/wsman/1/subscription";
const EVENTING_NS: &str = "http://schemas.xmlsoap.org/ws/2004/08/eventing";
const ENUMERATION_NS: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";
const POLICY_NS: &str = "http://schemas.xmlsoap.org/ws/2002/12/policy";
const AUTH_NS: &str = "http://schemas.microsoft.com/wbem/wsman/1/authentication";
const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

pub const ANONYMOUS: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
pub const RESOURCE_EVENT_LOG: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog";
pub const SPNEGO_KERBEROS: &str =
    "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/http/spnego-kerberos";
pub const HTTPS_MUTUAL: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual";
pub const EVENT_QUERY: &str = "http://schemas.microsoft.com/win/2004/08/events/eventquery";

pub const ACTION_EVENTS: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Events";
pub const ACTION_SUBSCRIBE: &str = "http://schemas.xmlsoap.org/ws/2004/08/eventing/Subscribe";
pub const ACTION_ENUMERATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
pub const ACTION_ENUMERATE_RESPONSE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/enumeration/EnumerateResponse";
pub const ACTION_END: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman/End";
pub const ACTION_SUBSCRIPTION_END: &str =
    "http://schemas.xmlsoap.org/ws/2004/08/eventing/SubscriptionEnd";
pub const ACTION_HEARTBEAT: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Heartbeat";
pub const ACTION_ACK: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman/Ack";

pub fn new_uuid() -> String {
    format!("uuid:{}", Uuid::new_v4().to_string().to_uppercase())
}

pub trait Serializable {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()>;
}

#[derive(Debug)]
pub struct Subscription {
    pub version: String,
    pub header: Header,
    pub body: SubscriptionBody,
}

impl Serializable for Subscription {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()> {
        writer
            .create_element("m:Subscription")
            .with_attribute(("xmlns:m", SUBSCRIPTION_NS))
            .write_inner_content(|writer| {
                writer
                    .create_element("m:Version")
                    .write_text_content(BytesText::new(
                        format!("uuid:{}", self.version).as_str(),
                    ))?;
                writer
                    .create_element("s:Envelope")
                    .with_attribute(("xmlns:s", SOAP_ENVELOPE_NS))
                    .with_attribute(("xmlns:a", ADDRESSING_NS))
                    .with_attribute(("xmlns:e", EVENTING_NS))
                    .with_attribute(("xmlns:n", ENUMERATION_NS))
                    .with_attribute(("xmlns:w", WSMAN_NS))
                    .with_attribute(("xmlns:p", MS_WSMAN_NS))
                    .write_inner_content(|writer| {
                        self.header.serialize(writer)?;
                        self.body.serialize(writer)?;
                        Ok::<(), quick_xml::Error>(())
                    })?;
                Ok::<(), quick_xml::Error>(())
            })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SubscriptionBody {
    // Heartbeats interval in seconds
    pub heartbeat_interval: u64,
    pub identifier: String,
    pub bookmark: Option<String>,
    pub query: String,
    pub address: String,
    pub connection_retry_interval: u32,
    pub connection_retry_count: u16,
    pub max_time: u32,
    pub max_elements: Option<u32>,
    pub max_envelope_size: u32,
    pub thumbprint: Option<String>,
    pub public_version: String,
    pub revision: Option<String>,
    pub locale: Option<String>,
    pub data_locale: Option<String>,
}

impl Serializable for SubscriptionBody {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()> {
        writer
            .create_element("s:Body")
            .write_inner_content(|writer| {
                writer
                    .create_element("e:Subscribe")
                    .write_inner_content(|writer| {
                        writer
                            .create_element("e:EndTo")
                            .write_inner_content(|writer| {
                                writer
                                    .create_element("a:Address")
                                    .write_text_content(BytesText::new(&self.address))?;
                                writer
                                    .create_element("a:ReferenceParameters")
                                    .write_inner_content(|writer| {
                                        writer
                                            .create_element("e:Identifier")
                                            .write_text_content(BytesText::new(&self.identifier))?;
                                        writer
                                            .create_element("Version")
                                            .write_text_content(BytesText::new(&self.public_version))?;
                                        if let Some(revision) = &self.revision {
                                            writer
                                                .create_element("Revision")
                                                .write_text_content(BytesText::new(revision))?;
                                        }
                                        Ok::<(), quick_xml::Error>(())
                                    })?;
                                Ok::<(), quick_xml::Error>(())
                            })?;
                        writer
                            .create_element("e:Delivery")
                            .with_attribute(("Mode", ACTION_EVENTS))
                            .write_inner_content(|writer| {
                                writer.create_element("w:Heartbeats").write_text_content(
                                    BytesText::new(
                                        format!("PT{}.000S", &self.heartbeat_interval).as_str(),
                                    ),
                                )?;
                                writer.create_element("e:NotifyTo").write_inner_content(
                                    |writer| {
                                        writer
                                            .create_element("a:Address")
                                            .write_text_content(BytesText::new(&self.address))?;
                                        writer
                                            .create_element("a:ReferenceParameters")
                                            .write_inner_content(|writer| {
                                                writer
                                                    .create_element("e:Identifier")
                                                    .write_text_content(BytesText::new(&self.identifier))?;
                                                writer
                                                    .create_element("Version")
                                                    .write_text_content(BytesText::new(&self.public_version))?;
                                                if let Some(revision) = &self.revision {
                                                    writer
                                                        .create_element("Revision")
                                                        .write_text_content(BytesText::new(revision))?;
                                                }
                                                Ok::<(), quick_xml::Error>(())
                                            })?;
                                        writer
                                            .create_element("c:Policy")
                                            .with_attribute(("xmlns:c", POLICY_NS))
                                            .with_attribute(("xmlns:auth", AUTH_NS))
                                            .write_inner_content(|writer| {
                                                writer
                                                    .create_element("c:ExactlyOne")
                                                    .write_inner_content(|writer| {
                                                        writer
                                                            .create_element("c:All")
                                                            // if thumbprint is defined, then we are using Tls
                                                            .write_inner_content(|writer| {
                                                                if let Some(tmb) = &self.thumbprint {
                                                                    // ---- BEGIN TLS ---- //
                                                                    writer
                                                                        .create_element(
                                                                            "auth:Authentication",
                                                                        )
                                                                        .with_attribute((
                                                                            "Profile",
                                                                            HTTPS_MUTUAL,
                                                                        ))
                                                                        .write_inner_content(|writer| {
                                                                            writer
                                                                            .create_element(
                                                                                "auth:ClientCertificate",
                                                                            )
                                                                            .write_inner_content(|writer| {
                                                                                writer
                                                                                .create_element(
                                                                                    "auth:Thumbprint",
                                                                                )
                                                                                .with_attribute((
                                                                                    "Role",
                                                                                    "issuer",
                                                                                ))
                                                                                .write_text_content(BytesText::new(
                                                                                    tmb,
                                                                                ))?;
                                                                                Ok::<(), quick_xml::Error>(())
                                                                            })?;
                                                                            Ok::<(), quick_xml::Error>(())
                                                                        })?;
                                                                    Ok::<(), quick_xml::Error>(())
                                                                    // ----- END TLS ----- //
                                                                }
                                                                else {
                                                                    // ---- BEGIN KRB ---- //
                                                                    writer
                                                                        .create_element(
                                                                            "auth:Authentication",
                                                                        )
                                                                        .with_attribute((
                                                                            "Profile",
                                                                            SPNEGO_KERBEROS,
                                                                        ))
                                                                        .write_empty()?;
                                                                    Ok::<(), quick_xml::Error>(())
                                                                    // ----- END KRB ----- //
                                                                }
                                                            })?;
                                                        Ok::<(), quick_xml::Error>(())
                                                    })?;
                                                Ok::<(), quick_xml::Error>(())
                                            })?;
                                        Ok::<(), quick_xml::Error>(())
                                    },
                                )?;
                                writer
                                    .create_element("w:ConnectionRetry")
                                    .with_attribute((
                                        "Total",
                                        format!("{}", self.connection_retry_count).as_str(),
                                    ))
                                    .write_text_content(BytesText::new(
                                        format!("PT{}.0S", self.connection_retry_interval).as_str(),
                                    ))?;
                                if let Some(max_elements) = &self.max_elements {
                                    writer.create_element("w:MaxElements").write_text_content(
                                        BytesText::new(format!("{}", max_elements).as_str()),
                                    )?;
                                }
                                writer.create_element("w:MaxTime").write_text_content(
                                    BytesText::new(format!("PT{}.000S", self.max_time).as_str()),
                                )?;
                                writer
                                    .create_element("w:MaxEnvelopeSize")
                                    .with_attribute(("Policy", "Notify"))
                                    .write_text_content(BytesText::new(
                                        format!("{}", self.max_envelope_size).as_str(),
                                    ))?;
                                if let Some(locale) = &self.locale {
                                    writer
                                        .create_element("w:Locale")
                                        .with_attribute(("xml:lang", locale.as_str()))
                                        .with_attribute(("s:mustUnderstand", "false"))
                                        .write_empty()?;
                                }
                                if let Some(data_locale) = &self.data_locale {
                                    writer
                                        .create_element("p:DataLocale")
                                        .with_attribute(("xml:lang", data_locale.as_str()))
                                        .with_attribute(("s:mustUnderstand", "false"))
                                        .write_empty()?;
                                }
                                writer
                                    .create_element("w:ContentEncoding")
                                    .write_text_content(BytesText::new("UTF-16"))?;
                                Ok::<(), quick_xml::Error>(())
                            })?;
                        writer
                            .create_element("w:Filter")
                            .with_attribute(("Dialect", EVENT_QUERY))
                            .write_inner_content(|writer| {
                                // Copy filter from "query" field
                                let mut reader = Reader::from_str(&self.query);
                                reader.config_mut().trim_text(true);
                                loop {
                                    match reader.read_event() {
                                        Ok(Event::Eof) => break,
                                        Ok(e) => writer.write_event(e)?,
                                        _ => (),
                                    };
                                }
                                Ok::<(), quick_xml::Error>(())
                            })?;
                        if let Some(bookmark) = &self.bookmark {
                            writer
                                .create_element("w:Bookmark")
                                .write_inner_content(|writer| {
                                    let mut reader = Reader::from_str(bookmark);
                                    reader.config_mut().trim_text(true);
                                    loop {
                                        match reader.read_event() {
                                            Ok(Event::Eof) => break,
                                            Ok(e) => writer.write_event(e)?,
                                            _ => (),
                                        };
                                    }
                                    Ok::<(), quick_xml::Error>(())
                                })?;
                        }
                        writer.create_element("w:SendBookmarks").write_empty()?;
                        Ok::<(), quick_xml::Error>(())
                    })?;
                Ok::<(), quick_xml::Error>(())
            })?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum OptionSetValue {
    String(String),
    Boolean(bool),
}

#[derive(Debug)]
pub struct Header {
    to: Option<String>,
    resource_uri: Option<String>,
    // Hostname of the source
    machine_id: Option<String>,
    reply_to: Option<String>,
    action: Option<String>,
    max_envelope_size: Option<u32>,
    message_id: Option<String>,
    // Might be interesting to keep this data if you want to translate things ?
    // Locale: String,
    // DataLocale: String,
    session_id: Option<String>,
    operation_id: Option<String>,
    sequence_id: Option<usize>,
    // OperationTimeout: String // Unused ?

    // Responses field
    relates_to: Option<String>,

    option_set: HashMap<String, OptionSetValue>,
    // Specific to Events
    identifier: Option<String>,
    bookmarks: Option<String>,
    ack_requested: Option<bool>,
    // Specific to Events and OpenWEC
    version: Option<String>,
    revision: Option<String>,
}

impl Header {
    fn empty() -> Self {
        Header {
            to: None,
            resource_uri: None,
            machine_id: None,
            reply_to: None,
            action: None,
            max_envelope_size: None,
            message_id: None,
            session_id: None,
            operation_id: None,
            sequence_id: None,
            relates_to: None,
            option_set: HashMap::new(),
            ack_requested: None,
            bookmarks: None,
            identifier: None,
            version: None,
            revision: None,
        }
    }
    pub fn new(
        to: String,
        uri: String,
        action: String,
        max_envelope_size: u32,
        message_id: Option<String>,
        session_id: Option<String>,
        operation_id: Option<String>,
        sequence_id: Option<usize>,
        options: HashMap<String, OptionSetValue>,
    ) -> Self {
        Header {
            to: Some(to),
            resource_uri: Some(uri),
            machine_id: None,
            reply_to: Some(ANONYMOUS.to_string()),
            action: Some(action),
            max_envelope_size: Some(max_envelope_size),
            message_id: Some(message_id.unwrap_or_else(new_uuid)),
            session_id,
            operation_id: Some(operation_id.unwrap_or_else(new_uuid)),
            sequence_id,
            relates_to: None,
            option_set: options,
            ack_requested: None,
            bookmarks: None,
            identifier: None,
            version: None,
            revision: None,
        }
    }

    /// Get a reference to the header's bookmarks.
    pub fn bookmarks(&self) -> Option<&String> {
        self.bookmarks.as_ref()
    }

    pub fn identifier(&self) -> Option<&String> {
        self.identifier.as_ref()
    }

    pub fn version(&self) -> Option<&String> {
        self.version.as_ref()
    }

    pub fn revision(&self) -> Option<&String> {
        self.revision.as_ref()
    }

    pub fn machine_id(&self) -> Option<&String> {
        self.machine_id.as_ref()
    }
}

impl Serializable for Header {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()> {
        writer
            .create_element("s:Header")
            .write_inner_content(|writer| {
                if let Some(to) = &self.to {
                    writer
                        .create_element("a:To")
                        .write_text_content(BytesText::new(to))?;
                }
                if let Some(uri) = &self.resource_uri {
                    writer
                        .create_element("w:ResourceURI")
                        .with_attribute(("s:mustUnderstand", "true"))
                        .write_text_content(BytesText::new(uri))?;
                }
                if let Some(reply_to) = &self.reply_to {
                    writer
                        .create_element("a:ReplyTo")
                        .write_inner_content(|writer| {
                            writer
                                .create_element("a:Address")
                                .with_attribute(("s:mustUnderstand", "true"))
                                .write_text_content(BytesText::new(reply_to))?;
                            Ok::<(), quick_xml::Error>(())
                        })?;
                }
                if let Some(action) = &self.action {
                    writer
                        .create_element("a:Action")
                        .with_attribute(("s:mustUnderstand", "true"))
                        .write_text_content(BytesText::new(action))?;
                }
                if let Some(max_envelope_size) = &self.max_envelope_size {
                    writer
                        .create_element("w:MaxEnvelopeSize")
                        .with_attribute(("s:mustUnderstand", "true"))
                        .write_text_content(BytesText::new(
                            format!("{}", max_envelope_size).as_str(),
                        ))?;
                }
                if let Some(message_id) = &self.message_id {
                    writer
                        .create_element("a:MessageID")
                        .write_text_content(BytesText::new(message_id))?;
                }
                if let Some(operation_id) = &self.operation_id {
                    writer
                        .create_element("p:OperationID")
                        .with_attribute(("s:mustUnderstand", "false"))
                        .write_text_content(BytesText::new(operation_id))?;
                }
                if let Some(sequence_id) = self.sequence_id {
                    writer
                        .create_element("p:SequenceId")
                        .with_attribute(("s:mustUnderstand", "false"))
                        .write_text_content(BytesText::new(format!("{}", sequence_id).as_str()))?;
                }
                if let Some(relates_to) = &self.relates_to {
                    writer
                        .create_element("a:RelatesTo")
                        .write_text_content(BytesText::new(relates_to))?;
                }
                if !self.option_set.is_empty() {
                    writer
                        .create_element("w:OptionSet")
                        .with_attribute(("xmlns:xsi", XSI_NS))
                        .write_inner_content(|writer| {
                            for (name, value) in &self.option_set {
                                match value {
                                    OptionSetValue::String(value) => writer
                                        .create_element("w:Option")
                                        .with_attribute(("Name", name.as_str()))
                                        .write_text_content(BytesText::new(value))?,
                                    OptionSetValue::Boolean(value) => writer
                                        .create_element("w:Option")
                                        .with_attribute(("Name", name.as_str()))
                                        .with_attribute((
                                            "xsi:nil",
                                            if *value { "true" } else { "false" },
                                        ))
                                        .write_empty()?,
                                };
                            }
                            Ok::<(), quick_xml::Error>(())
                        })?;
                }
                Ok::<(), quick_xml::Error>(())
            })?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Body {
    EnumerateResponse(Vec<Subscription>),
    Events(Vec<Arc<String>>),
}

impl Serializable for Body {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()> {
        match self {
            Body::EnumerateResponse(subscriptions) => {
                writer
                    .create_element("s:Body")
                    .write_inner_content(|writer| {
                        writer
                            .create_element("n:EnumerateResponse")
                            .write_inner_content(|writer| {
                                writer
                                    .create_element("n:EnumerationContext")
                                    .write_empty()?;
                                writer
                                    .create_element("w:Items")
                                    .write_inner_content(|writer| {
                                        for subscription in subscriptions {
                                            subscription.serialize(writer)?;
                                        }
                                        Ok::<(), quick_xml::Error>(())
                                    })?;
                                writer.create_element("w:EndOfSequence").write_empty()?;
                                Ok::<(), quick_xml::Error>(())
                            })?;
                        Ok::<(), quick_xml::Error>(())
                    })?;
            }
            x => {
                return Err(quick_xml::Error::Io(
                    std::io::Error::new(
                        ErrorKind::Other,
                        format!("Can not serialize body of {:?}", x),
                    )
                    .into(),
                ))
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Message {
    header: Header,
    pub body: Option<Body>,
}

impl Serializable for Message {
    fn serialize<W: std::io::Write>(&self, writer: &mut Writer<W>) -> quick_xml::Result<()> {
        writer
            .create_element("s:Envelope")
            .with_attribute(("xml:lang", "en-US"))
            .with_attribute(("xmlns:s", SOAP_ENVELOPE_NS))
            .with_attribute(("xmlns:a", ADDRESSING_NS))
            .with_attribute(("xmlns:n", ENUMERATION_NS))
            .with_attribute(("xmlns:w", WSMAN_NS))
            .with_attribute(("xmlns:p", MS_WSMAN_NS))
            .write_inner_content(|writer| {
                self.header.serialize(writer)?;
                match &self.body {
                    Some(body) => {
                        body.serialize(writer)?;
                    }
                    _ => {
                        writer.create_element("s:Body").write_empty()?;
                    }
                }
                Ok::<(), quick_xml::Error>(())
            })?;
        Ok(())
    }
}

impl Message {
    pub fn action(&self) -> Result<&str> {
        Ok(self
            .header
            .action
            .as_ref()
            .ok_or_else(|| anyhow!("Missing Action in message"))?)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn response_from(message: &Message, action: &str, body: Option<Body>) -> Result<Self> {
        Ok(Message {
            header: Header {
                to: Some(
                    message
                        .header
                        .reply_to
                        .as_ref()
                        .unwrap_or(&ANONYMOUS.to_owned())
                        .to_string(),
                ),
                resource_uri: None,
                machine_id: None,
                reply_to: None,
                action: Some(action.to_owned()),
                max_envelope_size: None,
                message_id: Some(new_uuid()),
                session_id: None,
                operation_id: None,
                sequence_id: Some(1),
                relates_to: Some(
                    message
                        .header
                        .message_id
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing Message ID in original message"))?
                        .clone(),
                ),
                option_set: HashMap::new(),
                ack_requested: None,
                bookmarks: None,
                identifier: None,
                version: None,
                revision: None,
            },
            body,
        })
    }
}

fn parse_header(header_node: Node) -> Result<Header> {
    let mut header = Header::empty();
    for node in header_node.children() {
        let tag = node.tag_name();
        if tag == (WSMAN_NS, "ResourceURI").into() {
            header.resource_uri = node.text().map(String::from);
        }
        if tag == (MACHINE_ID_NS, "MachineID").into() {
            header.machine_id = node.text().map(String::from);
        } else if tag == (ADDRESSING_NS, "To").into() {
            header.to = node.text().map(String::from);
        } else if tag == (ADDRESSING_NS, "ReplyTo").into() {
            for reply_to_node in node.children() {
                if reply_to_node.tag_name() == (ADDRESSING_NS, "Address").into() {
                    header.reply_to = reply_to_node.text().map(String::from);
                    break;
                }
            }
        } else if tag == (ADDRESSING_NS, "Action").into() {
            header.action = node.text().map(String::from);
        } else if tag == (WSMAN_NS, "MaxEnvelopeSize").into() {
            header.max_envelope_size = match node.text() {
                Some(text) => Some(text.parse()?),
                None => None,
            };
        } else if tag == (ADDRESSING_NS, "MessageID").into() {
            header.message_id = node.text().map(String::from);
        } else if tag == (MS_WSMAN_NS, "SessionId").into() {
            header.session_id = node.text().map(String::from);
        } else if tag == (MS_WSMAN_NS, "OperationID").into() {
            header.operation_id = node.text().map(String::from);
        } else if tag == (MS_WSMAN_NS, "SequenceId").into() {
            header.sequence_id = match node.text() {
                Some(text) => Some(text.parse()?),
                None => None,
            };
        } else if tag == (WSMAN_NS, "AckRequested").into() {
            header.ack_requested = Some(true)
        } else if tag == (WSMAN_NS, "Bookmark").into() {
            header.bookmarks = Some(String::from(
                &node.document().input_text()[node
                    .first_child()
                    .ok_or_else(|| anyhow!("No bookmarks!"))?
                    .range()],
            ));
        } else if tag == (EVENTING_NS, "Identifier").into() {
            header.identifier = node.text().map(String::from)
        } else if tag == "Version".into() {
            // specific to OpenWEC
            header.version = node.text().map(String::from)
        } else if tag == "Revision".into() {
            // specific to OpenWEC
            header.revision = node.text().map(String::from)
        }
    }
    Ok(header)
}

fn parse_body_events(node: Node) -> Result<Vec<Arc<String>>> {
    let mut events = Vec::new();
    ensure!(
        node.has_tag_name((SOAP_ENVELOPE_NS, "Body")),
        "Invalid Body tag"
    );
    for event in node
        .first_element_child()
        .ok_or_else(|| anyhow!("Malformed Events body"))?
        .children()
    {
        events.push(Arc::new(
            event
                .text()
                .ok_or_else(|| anyhow!("Missing Event body"))?
                .to_owned(),
        ))
    }
    Ok(events)
}

pub fn parse(payload: &str) -> Result<Message> {
    // This is only used if we need to replace invalid XML characters, but it must
    // be declared here because of scope level.
    let mut sanitized_payload = String::new();
    let doc = {
        let doc_res = Document::parse(payload);
        // Some events contain invalid XML characters (such as \u0x5 or \u0x4).
        // In that case, we try to replace these bad characters so that
        // the XML parsing can succeed.
        match doc_res {
            Ok(doc) => doc,
            Err(roxmltree::Error::NonXmlChar(c, pos)) => {
                debug!("Could not parse payload because of a non-XML character {:?} in CDATA at pos {}. Try to sanitize payload.", c, pos);
                trace!("Payload was {:?}", payload);
                sanitized_payload.reserve(payload.len());
                for c in payload.chars() {
                    if c.is_xml_char() {
                        sanitized_payload.push(c);
                    } else {
                        trace!(
                            "Character '{:?}' has been replaced by the string \"{:?}\"",
                            c,
                            c
                        );
                        sanitized_payload.push_str(format!("\\u{{{:x}}}", c as u32).as_ref());
                    }
                }
                Document::parse(&sanitized_payload)
                    .context("Could not parse SOAP message even with non-XML character removed")?
            }
            Err(err) => bail!(
                "Could not parse SOAP message: {:?}. Payload was {:?}",
                err,
                payload
            ),
        }
    };

    let root = doc.root_element();
    ensure!(
        root.has_tag_name((SOAP_ENVELOPE_NS, "Envelope")),
        "Invalid Envelope"
    );

    let mut header_opt: Option<Header> = None;
    let mut body_node_opt: Option<Node> = None;
    for node in root.children() {
        let tag = node.tag_name();
        if tag == (SOAP_ENVELOPE_NS, "Header").into() {
            header_opt = Some(parse_header(node).context("Failed to parse Header section")?);
        } else if tag == (SOAP_ENVELOPE_NS, "Body").into() {
            body_node_opt = Some(node)
        }
    }

    let header = header_opt.ok_or_else(|| anyhow!("Could not parse SOAP headers"))?;
    let mut body = None;

    // Parse body depending on Action field
    if header
        .action
        .as_ref()
        .ok_or_else(|| anyhow!("Missing Action header"))?
        == ACTION_EVENTS
    {
        body = Some(Body::Events(
            parse_body_events(
                body_node_opt.ok_or_else(|| anyhow!("Missing Body for Events message"))?,
            )
            .context("Failed to parse Body section for Events action")?,
        ));
    }

    Ok(Message { header, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_xml_char() {
        let payload = "<s:Envelope
	xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
	xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"
	xmlns:e=\"http://schemas.xmlsoap.org/ws/2004/08/eventing\"
	xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\"
	xmlns:p=\"http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd\">
	<s:Header>
		<a:To>http://srv.windomain.local:5985/wsman/subscriptions/B6BDBB59-FB07-4EE5-841F-EBEC9D67CDD4/1</a:To>
		<m:MachineID
			xmlns:m=\"http://schemas.microsoft.com/wbem/wsman/1/machineid\" s:mustUnderstand=\"false\">win10.windomain.local
		</m:MachineID>
		<a:ReplyTo>
			<a:Address s:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action s:mustUnderstand=\"true\">http://schemas.dmtf.org/wbem/wsman/1/wsman/Events</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand=\"true\">512000</w:MaxEnvelopeSize>
		<a:MessageID>uuid:31652DEB-C9E8-45D6-B3E8-90AC64D48422</a:MessageID>
		<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\" />
		<p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"false\" />
		<p:SessionId s:mustUnderstand=\"false\">uuid:981C530F-BE2A-4AAB-BACB-6FB4CD1A14AB</p:SessionId>
		<p:OperationID s:mustUnderstand=\"false\">uuid:C7F39CB2-8FFD-4DA3-A111-CDB303EEA098</p:OperationID>
		<p:SequenceId s:mustUnderstand=\"false\">1</p:SequenceId>
		<w:OperationTimeout>PT60.000S</w:OperationTimeout>
		<e:Identifier
			xmlns:e=\"http://schemas.xmlsoap.org/ws/2004/08/eventing\">219C5353-5F3D-4CD7-A644-F6B69E57C1C1
		</e:Identifier>
		<w:Bookmark>
			<BookmarkList>
				<Bookmark Channel=\"Microsoft-Windows-WinRM/Operational\" RecordId=\"149161\" IsCurrent=\"true\"/>
			</BookmarkList>
		</w:Bookmark>
		<w:AckRequested/>
	</s:Header>
	<s:Body>
		<w:Events><w:Event Action=\"http://schemas.dmtf.org/wbem/wsman/1/wsman/Event\"><![CDATA[<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM \x05 \' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>254</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000026</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:21.6986159Z\'/><EventRecordID>149141</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e5a0-11c2c7cdd801}\' RelatedActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>Activity Transfer</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Server</Keyword><Keyword>Activity Transfer</Keyword></Keywords></RenderingInfo></Event>]]></w:Event></w:Events>
	</s:Body>
    </s:Envelope>";
        assert!(Document::parse(payload).is_err());
        let doc = parse(payload).unwrap();
        match doc.body {
            Some(Body::Events(events)) => {
                println!("{:?}", events);
                assert_eq!(1, events.len());
                let event = events[0].clone();
                assert_eq!(event, Arc::new("<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-WinRM \\u{5} \' Guid=\'{a7975c8f-ac13-49f1-87da-5a984a4ab417}\'/><EventID>254</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x4000000000000026</Keywords><TimeCreated SystemTime=\'2022-09-21T14:48:21.6986159Z\'/><EventRecordID>149141</EventRecordID><Correlation ActivityID=\'{c2115b6c-cdc7-0000-e5a0-11c2c7cdd801}\' RelatedActivityID=\'{c2115b6c-cdc7-0000-a47b-11c2c7cdd801}\'/><Execution ProcessID=\'1100\' ThreadID=\'1452\'/><Channel>Microsoft-Windows-WinRM/Operational</Channel><Computer>win10.windomain.local</Computer><Security UserID=\'S-1-5-20\'/></System><EventData></EventData><RenderingInfo Culture=\'en-US\'><Message>Activity Transfer</Message><Level>Information</Level><Task></Task><Opcode>Info</Opcode><Channel>Microsoft-Windows-WinRM/Operational</Channel><Provider>Microsoft-Windows-Windows Remote Management</Provider><Keywords><Keyword>Client</Keyword><Keyword>Server</Keyword><Keyword>Activity Transfer</Keyword></Keywords></RenderingInfo></Event>".to_owned()));
            }
            _ => panic!("Wrong body type"),
        }
    }
}
