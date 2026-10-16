//! Wire protocol between the BaseHero app and its Keychain helper.
//!
//! A frame is a big-endian `u16` body length followed by the body. A request
//! names one fixed item and an operation; the helper derives the service and
//! account itself, so no request can name another service.
use std::io::{self, Read, Write};
pub use zeroize::Zeroizing;

pub mod process;

/// Largest frame body either side accepts.
pub const MAX_FRAME: usize = 128;
/// Largest item value the helper stores.
pub const MAX_VALUE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    Ordinary([u8; 32]),
    Receiver([u8; 32]),
    Control([u8; 32]),
    ControlPublic([u8; 32]),
    Setup([u8; 32]),
}

impl Item {
    fn code(&self) -> u8 {
        match self {
            Item::Ordinary(_) => 1,
            Item::Receiver(_) => 2,
            Item::Control(_) => 3,
            Item::ControlPublic(_) => 4,
            Item::Setup(_) => 5,
        }
    }
    fn from_code(code: u8, handle: [u8; 32]) -> Option<Self> {
        Some(match code {
            1 => Item::Ordinary(handle),
            2 => Item::Receiver(handle),
            3 => Item::Control(handle),
            4 => Item::ControlPublic(handle),
            5 => Item::Setup(handle),
            _ => return None,
        })
    }
    fn handle(&self) -> &[u8; 32] {
        match self {
            Item::Ordinary(h)
            | Item::Receiver(h)
            | Item::Control(h)
            | Item::ControlPublic(h)
            | Item::Setup(h) => h,
        }
    }
    fn role(&self) -> &'static str {
        match self {
            Item::Ordinary(_) => "ordinary",
            Item::Receiver(_) => "receiver",
            Item::Control(_) => "control",
            Item::ControlPublic(_) => "control-public",
            Item::Setup(_) => "setup",
        }
    }
    /// Appended to the bundle identifier to form the Keychain service.
    pub fn service_suffix(&self) -> &'static str {
        match self {
            Item::Setup(_) => ".pending-setup.login-v2",
            _ => ".device-keys.login-v1",
        }
    }
    /// The Keychain account: the handle in lowercase hex, `:`, the role.
    pub fn account(&self) -> String {
        use std::fmt::Write;
        let role = self.role();
        let mut account = String::with_capacity(64 + 1 + role.len());
        for byte in self.handle() {
            write!(account, "{byte:02x}").expect("writing to String");
        }
        account.push(':');
        account.push_str(role);
        account
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Read(Item),
    Add(Item, Zeroizing<Vec<u8>>),
    Delete(Item),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

const READ: u8 = 1;
const ADD: u8 = 2;
const DELETE: u8 = 3;

fn frame(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    debug_assert!(len <= MAX_FRAME);
    let mut out = Zeroizing::new(Vec::with_capacity(2 + len));
    out.extend_from_slice(&(len as u16).to_be_bytes());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

pub fn encode_request(request: &Request) -> Zeroizing<Vec<u8>> {
    let (op, item, value): (u8, &Item, &[u8]) = match request {
        Request::Read(item) => (READ, item, &[]),
        Request::Add(item, value) => (ADD, item, value),
        Request::Delete(item) => (DELETE, item, &[]),
    };
    frame(&[&[op, item.code()], item.handle(), value])
}

pub fn decode_request(body: &[u8]) -> Result<Request, Malformed> {
    let (&[op, code], rest) = body.split_first_chunk::<2>().ok_or(Malformed)?;
    let (handle, value) = rest.split_first_chunk::<32>().ok_or(Malformed)?;
    let item = Item::from_code(code, *handle).ok_or(Malformed)?;
    match (op, value.len()) {
        (READ, 0) => Ok(Request::Read(item)),
        (DELETE, 0) => Ok(Request::Delete(item)),
        (ADD, 1..=MAX_VALUE) => Ok(Request::Add(item, Zeroizing::new(value.to_vec()))),
        _ => Err(Malformed),
    }
}

/// Reads one frame body; `None` at a clean end of input before a frame.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 2];
    let mut got = 0;
    while got < 2 {
        match reader.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u16::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Keychain operations behind the protocol. Errors are OSStatus codes.
pub trait Store {
    fn read(&mut self, item: Item) -> Result<Zeroizing<Vec<u8>>, i32>;
    /// Adds a new item; never replaces an existing one.
    fn add(&mut self, item: Item, value: &[u8]) -> Result<(), i32>;
    fn delete(&mut self, item: Item) -> Result<(), i32>;
}

// A status that would claim success never accompanies a failure.
fn status(code: i32) -> i32 {
    if code == 0 { -1 } else { code }
}

/// Answers requests until the input ends. A malformed frame ends the loop
/// with an error and no reply.
pub fn serve(
    reader: &mut impl Read,
    writer: &mut impl Write,
    store: &mut impl Store,
) -> io::Result<()> {
    while let Some(body) = read_frame(reader)? {
        let request =
            decode_request(&body).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let reply = match request {
            Request::Read(item) => match store.read(item) {
                Ok(value) if (1..=MAX_VALUE).contains(&value.len()) => {
                    frame(&[&0i32.to_be_bytes(), &value])
                }
                Ok(_) => frame(&[&(-1i32).to_be_bytes()]),
                Err(code) => frame(&[&status(code).to_be_bytes()]),
            },
            Request::Add(item, value) => match store.add(item, &value) {
                Ok(()) => frame(&[&0i32.to_be_bytes()]),
                Err(code) => frame(&[&status(code).to_be_bytes()]),
            },
            Request::Delete(item) => match store.delete(item) {
                Ok(()) => frame(&[&0i32.to_be_bytes()]),
                Err(code) => frame(&[&status(code).to_be_bytes()]),
            },
        };
        writer.write_all(&reply)?;
        writer.flush()?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperError {
    /// The helper answered with this nonzero OSStatus.
    Status(i32),
    /// No well-formed answer: the helper is missing, refused us or broke the protocol.
    Unavailable,
}

/// One request at a time over a helper's stdin/stdout.
pub struct Client<R, W> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> Client<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    /// The value for a successful read; empty for a successful add or delete.
    pub fn call(&mut self, request: &Request) -> Result<Zeroizing<Vec<u8>>, HelperError> {
        let unavailable = |_| HelperError::Unavailable;
        self.writer
            .write_all(&encode_request(request))
            .map_err(unavailable)?;
        self.writer.flush().map_err(unavailable)?;
        let body = read_frame(&mut self.reader)
            .map_err(unavailable)?
            .ok_or(HelperError::Unavailable)?;
        let (code, value) = body
            .split_first_chunk::<4>()
            .ok_or(HelperError::Unavailable)?;
        let code = i32::from_be_bytes(*code);
        let reads = matches!(request, Request::Read(_));
        match (code, value.len()) {
            (0, 0) if !reads => Ok(Zeroizing::new(Vec::new())),
            (0, 1..=MAX_VALUE) if reads => Ok(Zeroizing::new(value.to_vec())),
            (0, _) => Err(HelperError::Unavailable),
            (code, 0) => Err(HelperError::Status(code)),
            _ => Err(HelperError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const H: [u8; 32] = [0xab; 32];

    #[test]
    fn items_name_todays_services_and_accounts() {
        let hex = "ab".repeat(32);
        for (item, suffix, role) in [
            (Item::Ordinary(H), ".device-keys.login-v1", "ordinary"),
            (Item::Receiver(H), ".device-keys.login-v1", "receiver"),
            (Item::Control(H), ".device-keys.login-v1", "control"),
            (
                Item::ControlPublic(H),
                ".device-keys.login-v1",
                "control-public",
            ),
            (Item::Setup(H), ".pending-setup.login-v2", "setup"),
        ] {
            assert_eq!(item.service_suffix(), suffix);
            assert_eq!(item.account(), format!("{hex}:{role}"));
        }
        let mut handle = [0u8; 32];
        handle[0] = 0x0f;
        handle[31] = 0xf0;
        let account = Item::Setup(handle).account();
        assert!(account.starts_with("0f00"), "{account}");
        assert!(account.ends_with("00f0:setup"), "{account}");
    }

    #[test]
    fn requests_encode_as_documented_frames() {
        let mut read = vec![0x00, 0x22, 0x01, 0x01];
        read.extend([0xab; 32]);
        assert_eq!(*encode_request(&Request::Read(Item::Ordinary(H))), read);
        let mut add = vec![0x00, 0x25, 0x02, 0x05];
        add.extend([0xab; 32]);
        add.extend([9, 8, 7]);
        assert_eq!(
            *encode_request(&Request::Add(Item::Setup(H), Zeroizing::new(vec![9, 8, 7]))),
            add
        );
        let mut delete = vec![0x00, 0x22, 0x03, 0x04];
        delete.extend([0xab; 32]);
        assert_eq!(
            *encode_request(&Request::Delete(Item::ControlPublic(H))),
            delete
        );
    }

    #[test]
    fn decoding_accepts_each_item_and_operation() {
        for (code, item) in [
            (1, Item::Ordinary(H)),
            (2, Item::Receiver(H)),
            (3, Item::Control(H)),
            (4, Item::ControlPublic(H)),
            (5, Item::Setup(H)),
        ] {
            let mut body = vec![1, code];
            body.extend(H);
            assert_eq!(decode_request(&body), Ok(Request::Read(item)));
            body[0] = 3;
            assert_eq!(decode_request(&body), Ok(Request::Delete(item)));
            body[0] = 2;
            body.push(0x55);
            assert_eq!(
                decode_request(&body),
                Ok(Request::Add(item, Zeroizing::new(vec![0x55])))
            );
        }
    }

    #[test]
    fn decoding_refuses_anything_else() {
        let body = |op: u8, item: u8, handle: usize, value: usize| {
            let mut b = vec![op, item];
            b.extend(vec![0xab; handle]);
            b.extend(vec![1; value]);
            b
        };
        for bad in [
            vec![],
            vec![1],
            body(0, 1, 32, 0), // unknown operation
            body(4, 1, 32, 0), // unknown operation
            body(1, 0, 32, 0), // unknown item
            body(1, 6, 32, 0), // unknown item
            body(1, 1, 31, 0), // short handle
            body(1, 1, 32, 1), // read carries no value
            body(3, 1, 32, 1), // delete carries no value
            body(2, 1, 32, 0), // add needs a value
            body(2, 1, 32, MAX_VALUE + 1),
        ] {
            assert_eq!(decode_request(&bad), Err(Malformed), "{bad:?}");
        }
        assert!(decode_request(&body(2, 1, 32, MAX_VALUE)).is_ok());
    }

    #[test]
    fn frames_are_bounded_before_allocation() {
        let mut oversized: &[u8] = &[0x00, 0x81, 0, 0];
        assert!(read_frame(&mut oversized).is_err());
        let mut huge: &[u8] = &[0xff, 0xff];
        assert!(read_frame(&mut huge).is_err());
        let mut truncated: &[u8] = &[0x00, 0x03, 1, 2];
        assert!(read_frame(&mut truncated).is_err());
        let mut half_length: &[u8] = &[0x00];
        assert!(read_frame(&mut half_length).is_err());
        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty).unwrap(), None);
        let mut one: &[u8] = &[0x00, 0x02, 7, 8, 0xee];
        assert_eq!(
            read_frame(&mut one).unwrap().map(|v| v.to_vec()),
            Some(vec![7, 8])
        );
        assert_eq!(one, &[0xee]);
    }

    /// Mirrors SecItem's results: -25300 not found, -25299 duplicate.
    #[derive(Default)]
    struct MemoryStore {
        items: HashMap<String, Vec<u8>>,
    }
    impl Store for MemoryStore {
        fn read(&mut self, item: Item) -> Result<Zeroizing<Vec<u8>>, i32> {
            let key = format!("{}{}", item.service_suffix(), item.account());
            self.items
                .get(&key)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(-25300)
        }
        fn add(&mut self, item: Item, value: &[u8]) -> Result<(), i32> {
            let key = format!("{}{}", item.service_suffix(), item.account());
            if self.items.contains_key(&key) {
                return Err(-25299);
            }
            self.items.insert(key, value.to_vec());
            Ok(())
        }
        fn delete(&mut self, item: Item) -> Result<(), i32> {
            let key = format!("{}{}", item.service_suffix(), item.account());
            self.items.remove(&key).map(|_| ()).ok_or(-25300)
        }
    }

    fn served<T>(
        store: MemoryStore,
        body: impl FnOnce(&mut Client<io::PipeReader, io::PipeWriter>) -> T,
    ) -> (T, io::Result<()>) {
        let (request_reader, request_writer) = io::pipe().unwrap();
        let (reply_reader, reply_writer) = io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let (mut reader, mut writer, mut store) = (request_reader, reply_writer, store);
            serve(&mut reader, &mut writer, &mut store)
        });
        let mut client = Client::new(reply_reader, request_writer);
        let result = body(&mut client);
        drop(client);
        (result, server.join().unwrap())
    }

    #[test]
    fn client_and_helper_round_trip_through_the_store() {
        let ((), ended) = served(MemoryStore::default(), |client| {
            let value = Zeroizing::new(vec![1u8; 34]);
            assert_eq!(
                client.call(&Request::Read(Item::Control(H))),
                Err(HelperError::Status(-25300))
            );
            assert_eq!(
                client
                    .call(&Request::Add(Item::Control(H), value.clone()))
                    .map(|v| v.to_vec()),
                Ok(vec![])
            );
            assert_eq!(
                client.call(&Request::Add(Item::Control(H), Zeroizing::new(vec![2; 34]))),
                Err(HelperError::Status(-25299)),
                "an existing item is never replaced"
            );
            assert_eq!(
                client
                    .call(&Request::Read(Item::Control(H)))
                    .map(|v| v.to_vec()),
                Ok(value.to_vec())
            );
            assert_eq!(
                client.call(&Request::Read(Item::ControlPublic(H))),
                Err(HelperError::Status(-25300)),
                "roles are separate items"
            );
            assert_eq!(
                client
                    .call(&Request::Delete(Item::Control(H)))
                    .map(|v| v.to_vec()),
                Ok(vec![])
            );
            assert_eq!(
                client.call(&Request::Read(Item::Control(H))),
                Err(HelperError::Status(-25300))
            );
        });
        assert!(ended.is_ok(), "{ended:?}");
    }

    #[test]
    fn a_malformed_request_ends_the_helper_without_a_reply() {
        let (request_reader, mut request_writer) = io::pipe().unwrap();
        let (mut reply_reader, reply_writer) = io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let (mut reader, mut writer) = (request_reader, reply_writer);
            serve(&mut reader, &mut writer, &mut MemoryStore::default())
        });
        let mut bad = vec![0x00, 0x22, 0x01, 0x09];
        bad.extend(H);
        request_writer.write_all(&bad).unwrap();
        assert!(server.join().unwrap().is_err());
        let mut reply = Vec::new();
        reply_reader.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty(), "{reply:?}");
    }

    /// A store bug must never reach the app as success or as an unbounded value.
    struct BrokenStore;
    impl Store for BrokenStore {
        fn read(&mut self, _: Item) -> Result<Zeroizing<Vec<u8>>, i32> {
            Ok(Zeroizing::new(vec![0; MAX_VALUE + 1]))
        }
        fn add(&mut self, _: Item, _: &[u8]) -> Result<(), i32> {
            Err(0)
        }
        fn delete(&mut self, _: Item) -> Result<(), i32> {
            Err(0)
        }
    }

    #[test]
    fn store_faults_are_reported_as_failures() {
        let (request_reader, request_writer) = io::pipe().unwrap();
        let (reply_reader, reply_writer) = io::pipe().unwrap();
        let server = std::thread::spawn(move || {
            let (mut reader, mut writer) = (request_reader, reply_writer);
            serve(&mut reader, &mut writer, &mut BrokenStore)
        });
        let mut client = Client::new(reply_reader, request_writer);
        assert_eq!(
            client.call(&Request::Read(Item::Ordinary(H))),
            Err(HelperError::Status(-1))
        );
        assert_eq!(
            client.call(&Request::Add(Item::Ordinary(H), Zeroizing::new(vec![1]))),
            Err(HelperError::Status(-1))
        );
        assert_eq!(
            client.call(&Request::Delete(Item::Ordinary(H))),
            Err(HelperError::Status(-1))
        );
        drop(client);
        assert!(server.join().unwrap().is_ok());
    }

    fn reply(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelperError> {
        let mut sink = Vec::new();
        let mut client = Client::new(bytes, &mut sink);
        client.call(&Request::Read(Item::Ordinary(H)))
    }
    fn reply_to_add(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelperError> {
        let mut sink = Vec::new();
        let mut client = Client::new(bytes, &mut sink);
        client.call(&Request::Add(Item::Ordinary(H), Zeroizing::new(vec![1])))
    }

    #[test]
    fn client_refuses_replies_that_do_not_fit_the_request() {
        assert_eq!(
            reply(&[0, 6, 0, 0, 0, 0, 4, 2]).map(|v| v.to_vec()),
            Ok(vec![4, 2])
        );
        assert_eq!(
            reply(&[0, 4, 0xff, 0xff, 0x9d, 0x2c]),
            Err(HelperError::Status(-25300))
        );
        assert_eq!(reply(&[]), Err(HelperError::Unavailable), "helper exited");
        assert_eq!(
            reply(&[0, 4, 0, 0, 0, 0]),
            Err(HelperError::Unavailable),
            "read success without a value"
        );
        assert_eq!(
            reply(&[0, 3, 0, 0, 0]),
            Err(HelperError::Unavailable),
            "short status"
        );
        assert_eq!(
            reply(&[0, 5, 0xff, 0xff, 0x9d, 0x2c, 1]),
            Err(HelperError::Unavailable),
            "failure with a value"
        );
        assert_eq!(
            reply_to_add(&[0, 4, 0, 0, 0, 0]).map(|v| v.to_vec()),
            Ok(vec![])
        );
        assert_eq!(
            reply_to_add(&[0, 5, 0, 0, 0, 0, 1]),
            Err(HelperError::Unavailable),
            "add returns no value"
        );
    }

    #[test]
    fn client_reports_a_closed_helper_as_unavailable() {
        let (reader, writer) = io::pipe().unwrap();
        drop(reader);
        let mut client = Client::new(&[][..], writer);
        assert_eq!(
            client.call(&Request::Read(Item::Ordinary(H))),
            Err(HelperError::Unavailable)
        );
    }
}
