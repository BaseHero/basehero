//! Bundled yrs engine under Pulley, with no imports or native parsing fallback.
//! Every public operation has one fuel budget, including allocations and
//! response extraction. On local failure discard the instance, not durable
//! state: the caller retries by opening its unchanged OrderedState.

use crate::note::{
    IncomingError, NoteError, OrderedState, WriterError, WriterPrefix, abi, count_rebuilds,
};
use std::{cell::Cell, sync::Mutex};
use wasmtime::{Instance, Memory, Store, StoreLimits, StoreLimitsBuilder, WasmParams};

pub const MEMORY_LIMIT: usize = 256 << 20;
/// Four times the rounded hostile fragmented-million-item measurement.
pub const FUEL: u64 = 4 * 3_220_000_000;
thread_local! {
    static FUEL_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
    static LAST_FUEL: Cell<u64> = const { Cell::new(0) };
}

/// Thread-local test scope; restores the setting even on unwind.
#[doc(hidden)]
pub fn with_fuel<T>(fuel: u64, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<u64>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FUEL_OVERRIDE.set(self.0);
        }
    }
    let _restore = Restore(FUEL_OVERRIDE.replace(Some(fuel)));
    f()
}
#[doc(hidden)]
pub fn last_fuel() -> u64 {
    LAST_FUEL.get()
}
fn budget() -> u64 {
    FUEL_OVERRIDE.get().unwrap_or(FUEL)
}
fn unavailable<T>(value: Option<T>) -> Result<T, NoteError> {
    value.ok_or(NoteError::Unavailable)
}

#[doc(hidden)]
pub fn module_imports() -> Result<Vec<(String, String)>, &'static str> {
    let (_, module) = bh_note_engine_artifact::module()?;
    Ok(module
        .imports()
        .map(|i| (i.module().to_owned(), i.name().to_owned()))
        .collect())
}

type Reply = Result<Vec<u8>, Vec<u8>>;
struct Guest {
    store: Store<StoreLimits>,
    instance: Instance,
    memory: Memory,
}
impl Guest {
    fn new(remaining: &mut u64) -> Result<Self, NoteError> {
        let (engine, module) =
            bh_note_engine_artifact::module().map_err(|_| NoteError::Unavailable)?;
        let limits = StoreLimitsBuilder::new()
            .memory_size(MEMORY_LIMIT)
            .instances(1)
            .memories(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(engine, limits);
        store.limiter(|l| l);
        store
            .set_fuel(*remaining)
            .map_err(|_| NoteError::Unavailable)?;
        let instance =
            Instance::new(&mut store, module, &[]).map_err(|_| NoteError::Unavailable)?;
        *remaining = store.get_fuel().map_err(|_| NoteError::Unavailable)?;
        let memory = unavailable(instance.get_memory(&mut store, "memory"))?;
        Ok(Self {
            store,
            instance,
            memory,
        })
    }
    fn invoke<P: WasmParams>(
        &mut self,
        remaining: &mut u64,
        name: &str,
        input: Option<&[u8]>,
        params: impl FnOnce(i32, i32) -> P,
    ) -> Result<Reply, NoteError> {
        self.store
            .set_fuel(*remaining)
            .map_err(|_| NoteError::Unavailable)?;
        let result = (|| -> Option<Reply> {
            let (ptr, len) = if let Some(bytes) = input {
                let len = i32::try_from(bytes.len()).ok()?;
                let alloc = self
                    .instance
                    .get_typed_func::<i32, i32>(&mut self.store, "alloc")
                    .ok()?;
                let ptr = alloc.call(&mut self.store, len).ok()?;
                self.memory
                    .write(&mut self.store, ptr as u32 as usize, bytes)
                    .ok()?;
                (ptr, len)
            } else {
                (0, 0)
            };
            let status = self
                .instance
                .get_typed_func::<P, i32>(&mut self.store, name)
                .ok()?
                .call(&mut self.store, params(ptr, len))
                .ok()?;
            let ptr = self.word("out_ptr")?;
            let len = self.word("out_len")?;
            // Validate arithmetic and the entire range before allocating host output.
            let bytes = self
                .memory
                .data(&self.store)
                .get(ptr..ptr.checked_add(len)?)?;
            let mut out = Vec::new();
            out.try_reserve_exact(bytes.len()).ok()?;
            out.extend_from_slice(bytes);
            match status {
                abi::OK => Some(Ok(out)),
                abi::ERR => Some(Err(out)),
                _ => None,
            }
        })();
        *remaining = self.store.get_fuel().map_err(|_| NoteError::Unavailable)?;
        unavailable(result)
    }
    fn word(&mut self, name: &str) -> Option<usize> {
        Some(
            self.instance
                .get_typed_func::<(), i32>(&mut self.store, name)
                .ok()?
                .call(&mut self.store, ())
                .ok()? as u32 as usize,
        )
    }
}
fn response(reply: Reply) -> Result<Vec<u8>, NoteError> {
    reply.map_err(|e| abi::read_note_error(&e).unwrap_or(NoteError::Unavailable))
}
fn scratch(remaining: &mut u64, name: &str, input: &[u8]) -> Result<Vec<u8>, NoteError> {
    response(Guest::new(remaining)?.invoke(remaining, name, Some(input), |p, l| (p, l))?)
}
fn operation<T>(f: impl FnOnce(&mut u64) -> Result<T, NoteError>) -> Result<T, NoteError> {
    let initial = budget();
    let mut remaining = initial;
    let result = f(&mut remaining);
    LAST_FUEL.set(initial.saturating_sub(remaining));
    result
}
pub(crate) fn is_update(bytes: &[u8]) -> Result<bool, NoteError> {
    operation(|b| unavailable(abi::read_bool(&scratch(b, "is_update", bytes)?)))
}
pub(crate) fn merge_updates(updates: &[Vec<u8>]) -> Result<Vec<u8>, NoteError> {
    let mut input = OrderedState::default();
    for update in updates {
        input.push(update.clone());
    }
    operation(|b| scratch(b, "merge_updates", &input.encode()))
}
pub(crate) fn classify_note(bytes: &[u8]) -> Result<bool, NoteError> {
    operation(|b| unavailable(abi::read_bool(&scratch(b, "classify", bytes)?)))
}

/// Disposable working note; only the owner/store can commit its results.
/// No operation on an unavailable instance fabricates a successful value.
pub struct Note {
    guest: Mutex<Option<Guest>>,
    replica: u64,
}
impl Note {
    pub fn new() -> Result<Self, NoteError> {
        Self::from_ordered(&OrderedState::default())
    }
    pub fn with_writer(client: u64) -> Result<Self, WriterError> {
        if client >= 1 << 53 {
            return Err(WriterError::InvalidWriter);
        }
        operation(|b| {
            let mut guest = Guest::new(b)?;
            let reply = guest.invoke(b, "create", None, |_, _| (client as i64, abi::WRITER))?;
            match reply {
                Ok(out) if out.is_empty() => Ok(Self {
                    guest: Mutex::new(Some(guest)),
                    replica: client,
                }),
                _ => Err(NoteError::Unavailable),
            }
        })
        .map_err(WriterError::Update)
    }
    pub fn from_ordered(state: &OrderedState) -> Result<Self, NoteError> {
        let replica = yrs::ClientID::random().get();
        operation(|b| {
            let mut guest = Guest::new(b)?;
            let out = response(guest.invoke(b, "open", Some(&state.encode()), |p, l| {
                (p, l, replica as i64)
            })?)?;
            if !out.is_empty() {
                return Err(NoteError::Unavailable);
            }
            Ok(Self {
                guest: Mutex::new(Some(guest)),
                replica,
            })
        })
    }
    fn with_guest<T>(
        &self,
        f: impl FnOnce(&mut Guest, &mut u64) -> Result<T, NoteError>,
    ) -> Result<T, NoteError> {
        let mut slot = self.guest.lock().map_err(|_| NoteError::Unavailable)?;
        let result = operation(|b| f(slot.as_mut().ok_or(NoteError::Unavailable)?, b));
        if matches!(result, Err(NoteError::Unavailable)) {
            *slot = None;
        }
        result
    }
    fn read<T>(
        &self,
        name: &str,
        client: Option<u64>,
        decode: fn(&[u8]) -> Option<T>,
    ) -> Result<T, NoteError> {
        self.with_guest(|g, b| {
            let reply = match client {
                None => g.invoke(b, name, None, |_, _| ()),
                Some(id) => g.invoke(b, name, None, |_, _| (id as i64,)),
            }?;
            unavailable(decode(&response(reply)?))
        })
    }
    fn apply(&self, name: &str, bytes: &[u8]) -> Result<(), NoteError> {
        self.with_guest(|g, b| {
            let out = response(g.invoke(b, name, Some(bytes), |p, l| (p, l))?)?;
            if out.is_empty() {
                Ok(())
            } else {
                Err(NoteError::Unavailable)
            }
        })
    }
    /// Decode with this note's existing guest, without allocating a second
    /// instance. As with other guest calls, a local failure invalidates it.
    pub fn is_update(&self, bytes: &[u8]) -> Result<bool, NoteError> {
        self.with_guest(|g, b| {
            let out = response(g.invoke(b, "is_update", Some(bytes), |p, l| (p, l))?)?;
            unavailable(abi::read_bool(&out))
        })
    }
    pub fn apply_update(&mut self, bytes: &[u8]) -> Result<(), NoteError> {
        self.apply("apply", bytes)
    }
    pub fn apply_ordered(&mut self, state: &OrderedState) -> Result<(), NoteError> {
        self.apply("apply_ordered", &state.encode())
    }
    pub fn apply_writer_update(&mut self, bytes: &[u8], client: u64) -> Result<(), WriterError> {
        self.with_guest(|g, b| {
            match g.invoke(b, "apply_writer", Some(bytes), |p, l| (p, l, client as i64))? {
                Ok(out) if out.is_empty() => Ok(Ok(())),
                Err(e) => match abi::read_writer_error(&e) {
                    Some(WriterError::Update(NoteError::Unavailable)) | None => {
                        Err(NoteError::Unavailable)
                    }
                    Some(e) => Ok(Err(e)),
                },
                _ => Err(NoteError::Unavailable),
            }
        })
        .map_err(WriterError::Update)?
    }
    pub fn apply_incoming(&mut self, bytes: &[u8], client: u64) -> Result<(), IncomingError> {
        self.with_guest(|g, b| {
            match g.invoke(b, "apply_incoming", Some(bytes), |p, l| {
                (p, l, client as i64)
            })? {
                Ok(out) if out.is_empty() => Ok(Ok(())),
                Err(e) => {
                    let (reason, changed) = unavailable(abi::read_refusal(&e))?;
                    Ok(Err(IncomingError::Refused { reason, changed }))
                }
                _ => Err(NoteError::Unavailable),
            }
        })
        .map_err(|_| IncomingError::Unavailable)?
    }
    pub fn state(&self) -> Result<Vec<u8>, NoteError> {
        self.read("state", None, |b| Some(b.to_vec()))
    }
    pub fn digest(&self) -> Result<[u8; 32], NoteError> {
        self.read("digest", None, |b| b.try_into().ok())
    }
    pub fn title_preview(&self) -> Result<String, NoteError> {
        self.read("title_preview", None, |b| {
            String::from_utf8(b.to_vec()).ok()
        })
    }
    pub fn document_positions(&self) -> Result<usize, NoteError> {
        self.read("document_positions", None, |b| {
            usize::try_from(u64::from_le_bytes(b.try_into().ok()?)).ok()
        })
    }
    pub fn has_writer(&self, id: u64) -> Result<bool, NoteError> {
        self.read("has_writer", Some(id), abi::read_bool)
    }
    pub fn writer_prefix(&self, id: u64) -> Result<WriterPrefix, NoteError> {
        self.read("writer_prefix", Some(id), abi::read_prefix)
    }
    pub fn writer_end(&self, id: u64) -> Result<Option<u32>, NoteError> {
        Ok(match self.writer_prefix(id)? {
            WriterPrefix::Ready(end) => Some(end),
            _ => None,
        })
    }
    pub fn has_pending(&self) -> Result<bool, NoteError> {
        self.read("has_pending", None, abi::read_bool)
    }
    pub fn replica_id(&self) -> u64 {
        self.replica
    }
    pub fn merged(&self) -> Result<Option<OrderedState>, NoteError> {
        self.compact(None)
    }
    pub fn ordered(
        &self,
        previous: &OrderedState,
        tail: &[Vec<u8>],
    ) -> Result<Option<OrderedState>, NoteError> {
        self.compact(Some((previous, tail)))
    }
    fn compact(
        &self,
        previous: Option<(&OrderedState, &[Vec<u8>])>,
    ) -> Result<Option<OrderedState>, NoteError> {
        self.with_guest(|g, b| {
            let state = response(g.invoke(b, "state", None, |_, _| ())?)?;
            let digest = response(g.invoke(b, "digest", None, |_, _| ())?)?;
            if digest.len() != 32 {
                return Err(NoteError::Unavailable);
            }
            let reply = if let Some((previous, tail)) = previous {
                let mut rest = OrderedState::default();
                for update in tail {
                    rest.push(update.clone());
                }
                scratch(
                    b,
                    "ordered",
                    &abi::framed(&[&digest, &state, &previous.encode(), &rest.encode()]),
                )?
            } else {
                scratch(b, "merged", &abi::framed(&[&digest, &state]))?
            };
            let (rebuilds, found) = unavailable(abi::read_rebuilt(&reply))?;
            if rebuilds > crate::note::ORDERED_REBUILD_BUDGET {
                return Err(NoteError::Unavailable);
            }
            count_rebuilds(rebuilds);
            match found {
                None => Ok(None),
                Some(bytes) if previous.is_some() => OrderedState::decode(bytes)
                    .map(Some)
                    .map_err(|_| NoteError::Unavailable),
                Some([]) => Ok(Some(OrderedState::single(state))),
                Some(_) => Err(NoteError::Unavailable),
            }
        })
    }
    pub fn try_append_paragraph(&mut self, text: &str) -> Result<Vec<u8>, WriterError> {
        self.with_guest(|g, b| {
            match g.invoke(b, "try_append_paragraph", Some(text.as_bytes()), |p, l| {
                (p, l)
            })? {
                Ok(out) => Ok(Ok(out)),
                Err(e) => match abi::read_writer_error(&e) {
                    Some(WriterError::Update(NoteError::Unavailable)) | None => {
                        Err(NoteError::Unavailable)
                    }
                    Some(e) => Ok(Err(e)),
                },
            }
        })
        .map_err(WriterError::Update)?
    }
    /// Unchecked fixture authoring, still fallible at the containment boundary.
    pub fn append_paragraph(&mut self, text: &str) -> Result<Vec<u8>, NoteError> {
        self.with_guest(|g, b| {
            response(g.invoke(b, "append_paragraph", Some(text.as_bytes()), |p, l| (p, l))?)
        })
    }
    #[doc(hidden)]
    pub fn memory_bytes(&self) -> Result<usize, NoteError> {
        let slot = self.guest.lock().map_err(|_| NoteError::Unavailable)?;
        let g = slot.as_ref().ok_or(NoteError::Unavailable)?;
        Ok(g.memory.data_size(&g.store))
    }
}
