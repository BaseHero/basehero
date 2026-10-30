use bh_proto::{AccountId, BaseId, DeviceId, KdfParams, ObjectId};
use serde::{Deserialize, Serialize, Serializer};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileKind {
    Keys = 1,
    Snapshot = 2,
    Log = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Damage {
    Format,
    Kind,
    NoClosing,
    Checksum,
}

pub(crate) fn encode(kind: FileKind, records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"BHBK\x01".to_vec();
    out.push(kind as u8);
    for body in records {
        assert!(!body.is_empty() && u32::try_from(body.len()).is_ok());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    }
    let hash = bh_crypto::sha256(&out);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(records.len() as u64).to_be_bytes());
    out.extend_from_slice(&hash);
    out
}

pub(crate) fn decode(kind: FileKind, bytes: &[u8]) -> Result<Vec<&[u8]>, Damage> {
    if bytes.len() < 6 {
        return Err(Damage::NoClosing);
    }
    if &bytes[..5] != b"BHBK\x01" {
        return Err(Damage::Format);
    }
    if bytes[5] != kind as u8 {
        return Err(Damage::Kind);
    }
    let mut cursor = 6;
    let mut records = Vec::new();
    loop {
        let length = read::<4>(bytes, &mut cursor).ok_or(Damage::NoClosing)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 {
            let count = u64::from_be_bytes(read::<8>(bytes, &mut cursor).ok_or(Damage::NoClosing)?);
            let hash = read::<32>(bytes, &mut cursor).ok_or(Damage::NoClosing)?;
            if cursor != bytes.len() {
                return Err(Damage::Format);
            }
            if count != records.len() as u64 || hash != bh_crypto::sha256(&bytes[..cursor - 44]) {
                return Err(Damage::Checksum);
            }
            return Ok(records);
        }
        let end = cursor.checked_add(length).ok_or(Damage::NoClosing)?;
        let body = bytes.get(cursor..end).ok_or(Damage::NoClosing)?;
        records.push(body);
        cursor = end;
    }
}

fn read<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let value = bytes
        .get(*cursor..(*cursor).checked_add(N)?)?
        .try_into()
        .ok()?;
    *cursor += N;
    Some(value)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChangeRecord<'a> {
    pub state: bool,
    pub base: BaseId,
    pub object: ObjectId,
    pub run: i64,
    pub sealed: &'a [u8],
}

impl<'a> ChangeRecord<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.sealed.len());
        out.push(u8::from(self.state));
        out.extend_from_slice(&self.base.0);
        out.extend_from_slice(&self.object.0);
        out.extend_from_slice(&self.run.to_be_bytes());
        out.extend_from_slice(self.sealed);
        out
    }

    pub fn decode(body: &'a [u8]) -> Result<Self, Damage> {
        let (state, tail) = body.split_first().ok_or(Damage::Format)?;
        if *state > 1 || tail.len() <= 40 {
            return Err(Damage::Format);
        }
        let mut cursor = 1;
        let base = BaseId(read::<16>(body, &mut cursor).ok_or(Damage::Format)?);
        let object = ObjectId(read::<16>(body, &mut cursor).ok_or(Damage::Format)?);
        let run = i64::from_be_bytes(read::<8>(body, &mut cursor).ok_or(Damage::Format)?);
        Ok(Self {
            state: *state == 1,
            base,
            object,
            run,
            sealed: &body[cursor..],
        })
    }
}

mod binary {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        URL_SAFE_NO_PAD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeysFile {
    pub v: u8,
    pub account: AccountId,
    pub device: DeviceId,
    pub server: String,
    pub email: String,
    pub written_at: i64,
    #[serde(with = "binary")]
    pub salt: Vec<u8>,
    pub kdf: KdfParams,
    #[serde(with = "binary")]
    pub envelope: Vec<u8>,
    pub envelope_checked: bool,
    #[serde(serialize_with = "serialize_wrappers")]
    pub wrappers: Vec<Wrapper>,
    pub account_data: Option<SealedData>,
}

fn serialize_wrappers<S: Serializer>(
    wrappers: &[Wrapper],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut sorted: Vec<_> = wrappers.iter().collect();
    sorted.sort_by_key(|wrapper| wrapper.base);
    sorted.serialize(serializer)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Wrapper {
    pub base: BaseId,
    pub epoch: u64,
    #[serde(with = "binary")]
    pub wrapper: Vec<u8>,
    /// Older base keys, sealed under their successor (absent in older keys files).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<PreviousKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreviousKey {
    pub epoch: u32,
    #[serde(with = "binary")]
    pub sealed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SealedData {
    pub version: u64,
    #[serde(with = "binary")]
    pub sealed: Vec<u8>,
}

pub(crate) fn run_name(ms: i64) -> String {
    let time = OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .expect("run timestamp outside supported calendar range");
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    )
}

pub(crate) fn parse_run(name: &str) -> Option<i64> {
    let b = name.as_bytes();
    if b.len() != 19
        || b[8] != b'T'
        || b[18] != b'Z'
        || !b
            .iter()
            .enumerate()
            .all(|(i, c)| i == 8 || i == 18 || c.is_ascii_digit())
    {
        return None;
    }
    let num = |a, z| name.get(a..z)?.parse::<u8>().ok();
    let year = name.get(0..4)?.parse::<i32>().ok()?;
    let date =
        Date::from_calendar_date(year, Month::try_from(num(4, 6)?).ok()?, num(6, 8)?).ok()?;
    let time = Time::from_hms_milli(
        num(9, 11)?,
        num(11, 13)?,
        num(13, 15)?,
        name.get(15..18)?.parse().ok()?,
    )
    .ok()?;
    i64::try_from(
        PrimitiveDateTime::new(date, time)
            .assume_utc()
            .unix_timestamp_nanos()
            / 1_000_000,
    )
    .ok()
}

#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn device_dir(a: AccountId, d: DeviceId) -> String {
    format!("{a}/{d}")
}
#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn keys_path(run: &str) -> String {
    format!("keys/{run}.bhk")
}
#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn snapshot_path(base: BaseId, run: &str) -> String {
    format!("snapshots/{base}/{run}.bhs")
}
#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn log_path(run: &str) -> String {
    format!("log/{run}.bhl")
}
#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn merged_path(day: &str, run: &str) -> String {
    format!("log/{day}-{run}.bhl")
}
#[allow(
    dead_code,
    reason = "backup writer and reader use device-relative paths"
)]
pub(crate) fn part_path(base: BaseId, object: ObjectId, n: u32) -> String {
    format!("files/{base}/{object}/{n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_file_round_trips_and_counts_its_records() {
        let bytes = encode(FileKind::Log, &[b"a".to_vec(), b"bc".to_vec()]);
        assert_eq!(&bytes[..6], b"BHBK\x01\x03");
        assert_eq!(
            decode(FileKind::Log, &bytes).unwrap(),
            vec![&b"a"[..], &b"bc"[..]]
        );
    }

    #[test]
    fn any_truncation_is_refused() {
        let bytes = encode(FileKind::Snapshot, &[vec![7; 100], vec![8; 3]]);
        for n in 0..bytes.len() {
            assert!(decode(FileKind::Snapshot, &bytes[..n]).is_err(), "{n}");
        }
    }

    #[test]
    fn a_flipped_byte_fails_the_checksum() {
        let mut bytes = encode(FileKind::Log, &[vec![7; 100]]);
        bytes[10] ^= 1;
        assert_eq!(decode(FileKind::Log, &bytes), Err(Damage::Checksum));
    }

    #[test]
    fn another_kind_is_refused() {
        let bytes = encode(FileKind::Keys, &[b"a".to_vec()]);
        assert_eq!(decode(FileKind::Log, &bytes), Err(Damage::Kind));
    }

    #[test]
    fn bytes_after_the_closing_record_are_refused() {
        let mut bytes = encode(FileKind::Keys, &[b"a".to_vec()]);
        bytes.push(0);
        assert!(decode(FileKind::Keys, &bytes).is_err());
    }

    #[test]
    fn change_records_keep_their_header() {
        let record = ChangeRecord {
            state: true,
            base: BaseId([1; 16]),
            object: ObjectId([2; 16]),
            run: 1793268900123,
            sealed: b"sealed",
        };
        let body = record.encode();
        let restored = ChangeRecord::decode(&body).unwrap();
        assert_eq!(
            (
                restored.state,
                restored.base,
                restored.object,
                restored.run,
                restored.sealed
            ),
            (
                true,
                BaseId([1; 16]),
                ObjectId([2; 16]),
                1793268900123,
                &b"sealed"[..]
            )
        );
        assert_eq!(ChangeRecord::decode(&body[..40]), Err(Damage::Format));
    }

    #[test]
    fn run_names_sort_by_time_and_parse_back() {
        assert_eq!(run_name(1_793_268_900_123), "20261029T101500123Z");
        assert_eq!(parse_run("20261029T101500123Z"), Some(1_793_268_900_123));
        assert!(run_name(1) < run_name(2));
        assert_eq!(parse_run("20261029T251500123Z"), None);
    }

    #[test]
    fn keys_serialize_wrappers_in_base_order() {
        let keys = KeysFile {
            v: 1,
            account: AccountId([1; 16]),
            device: DeviceId([2; 16]),
            server: String::new(),
            email: String::new(),
            written_at: 0,
            salt: vec![],
            kdf: KdfParams {
                ops_limit: 3,
                mem_limit_kib: 65536,
            },
            envelope: vec![],
            envelope_checked: false,
            wrappers: vec![
                Wrapper {
                    base: BaseId([9; 16]),
                    epoch: 1,
                    wrapper: vec![9],
                    chain: vec![],
                },
                Wrapper {
                    base: BaseId([3; 16]),
                    epoch: 2,
                    wrapper: vec![3],
                    chain: vec![],
                },
            ],
            account_data: None,
        };
        let value = serde_json::to_value(&keys).unwrap();
        assert_eq!(
            value["wrappers"][0]["base"],
            "03030303030303030303030303030303"
        );
        assert_eq!(
            value["wrappers"][1]["base"],
            "09090909090909090909090909090909"
        );
    }

    #[test]
    fn keys_have_camel_case_and_unpadded_binary() {
        let keys = KeysFile {
            v: 1,
            account: AccountId([1; 16]),
            device: DeviceId([2; 16]),
            server: "https://api.basehero.com/".into(),
            email: "dan@example.com".into(),
            written_at: 1793268900123,
            salt: vec![255],
            kdf: bh_proto::KdfParams {
                ops_limit: 3,
                mem_limit_kib: 65536,
            },
            envelope: vec![254],
            envelope_checked: true,
            wrappers: vec![Wrapper {
                base: BaseId([3; 16]),
                epoch: 1,
                wrapper: vec![253],
                chain: vec![],
            }],
            account_data: Some(SealedData {
                version: 12,
                sealed: vec![252],
            }),
        };
        let value = serde_json::to_value(&keys).unwrap();
        assert_eq!(value["writtenAt"], 1793268900123_i64);
        assert_eq!(value["envelopeChecked"], true);
        assert_eq!(value["salt"], "_w");
        assert_eq!(value["envelope"], "_g");
        assert_eq!(value["wrappers"][0]["wrapper"], "_Q");
        assert_eq!(value["accountData"]["sealed"], "_A");
        assert_eq!(value["kdf"]["opsLimit"], 3);
        assert_eq!(value["kdf"]["memLimitKib"], 65536);
        assert_eq!(serde_json::from_value::<KeysFile>(value).unwrap(), keys);
    }
}
