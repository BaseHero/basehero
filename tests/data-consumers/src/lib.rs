//! Independent synthetic consumers and their headless, in-process test harness.
//! Authority here is assumed authenticated, not a production login path.
pub mod article;
pub mod journal;
pub mod recipe;
pub mod selection;

use bh_data::{
    Actor, AppId, FieldPath, RecordId, RecordRef, RevisionId, Scope, TypeId,
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
        pending::LocalSaved,
    },
    query::{Query, TypeSelect},
    session::{DataSession, Store},
    testkit::{Delivery, OrderedLog, Replica},
    text::{self, BodyText},
};
use bh_data_fixtures::{FixtureAuthority, member};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
pub const CONTEXT: &[u8] = include_bytes!("../types/Project.json");
pub fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
pub fn reference(record: RecordId) -> RecordRef {
    RecordRef {
        audience: None,
        record,
    }
}
pub fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
pub fn set(s: &str, value: Value) -> FieldChange {
    FieldChange {
        path: path(s),
        value: Some(value),
    }
}
pub fn authority(actor: Actor, reads: Vec<Scope>, write: Option<Scope>) -> FixtureAuthority {
    FixtureAuthority {
        actor,
        reads,
        write,
    }
}
pub fn session(
    replica: &Replica,
    scope: Scope,
    actor: Actor,
) -> DataSession<&Replica, FixtureAuthority> {
    DataSession::new(replica, authority(actor, vec![scope], Some(scope)))
}
pub fn all(type_id: TypeId) -> Query {
    Query {
        select: TypeSelect::Exact(type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}

/// Fixture body source; typed documents never contain these strings.
#[derive(Default)]
pub struct Bodies(pub BTreeMap<(Scope, RecordId), String>);
impl BodyText for Bodies {
    fn body_text(
        &self,
        scope: Scope,
        record: RecordId,
    ) -> Result<Option<String>, bh_data::DataError> {
        Ok(self.0.get(&(scope, record)).cloned())
    }
}
pub fn project(replica: &Replica, scope: Scope, record: RecordId, title: &str, bodies: &Bodies) {
    replica
        .write(|tx| bh_data::note::upsert_projection(tx, scope, record, title))
        .unwrap();
    // Body reads happen outside the transaction, exactly as the host contract requires.
    for job in text::next_jobs(replica.conn(), 100).unwrap() {
        if let Some(body) = bodies.body_text(job.scope, job.record).unwrap() {
            replica
                .write(|tx| text::store_extracted(tx, &job, &body))
                .unwrap();
        }
    }
}

pub struct Harness {
    pub replicas: Vec<Replica>,
    pub actors: Vec<Actor>,
    pub log: OrderedLog,
    pub bodies: Bodies,
}
impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}
impl Harness {
    pub fn new() -> Self {
        Self {
            replicas: vec![
                Replica::new_in_memory().unwrap(),
                Replica::new_in_memory().unwrap(),
            ],
            actors: vec![member(1), member(2)],
            log: OrderedLog::new(),
            bodies: Bodies::default(),
        }
    }
    pub fn session(&self, replica: usize) -> DataSession<&Replica, FixtureAuthority> {
        session(
            &self.replicas[replica],
            SHARED,
            self.actors[replica].clone(),
        )
    }
    pub fn accept(&mut self, author: usize, saved: LocalSaved) {
        self.log.append(SHARED, &self.actors[author], saved.payload);
        for replica in &mut self.replicas {
            let outcomes = replica.sync_from(&self.log, Delivery::InOrder).unwrap();
            assert!(
                outcomes
                    .iter()
                    .all(|(_, o)| matches!(o, Outcome::Accepted { .. })),
                "{outcomes:?}"
            );
        }
    }
    pub fn apply(&mut self, author: usize, op: Operation) {
        let saved = self.session(author).submit(op).unwrap();
        self.accept(author, saved);
    }
    pub fn install(&mut self) {
        for (app, name) in [
            (article::APP, "Article reader"),
            (selection::APP, "Source selection"),
            (AppId([4; 32]), "Workspace context"),
        ] {
            self.apply(
                0,
                Operation::DefineApp {
                    app,
                    name: name.into(),
                },
            );
        }
        for bytes in [CONTEXT, recipe::ADDRESS] {
            self.apply(
                0,
                Operation::DefineType {
                    bytes: bytes.to_vec(),
                },
            );
        }
        let saved = article::define(&self.session(0)).unwrap();
        self.accept(0, saved);
        let saved = selection::define(&self.session(1)).unwrap();
        self.accept(1, saved);
        let saved = journal::define(&self.session(0)).unwrap();
        self.accept(0, saved);
        let saved = recipe::define(&self.session(1)).unwrap();
        self.accept(1, saved);
    }
    pub fn context(&mut self, record: RecordId, name: &str) {
        self.apply(
            1,
            Operation::Create {
                record,
                type_id: TypeId::for_app(AppId([4; 32]), [10; 16]),
                revision: RevisionId::of(CONTEXT),
                doc: json!({"name":name}),
            },
        );
    }
    pub fn project_note(&mut self, record: RecordId, title: &str, body: &str) {
        self.bodies.0.insert((SHARED, record), body.into());
        for replica in &self.replicas {
            project(replica, SHARED, record, title, &self.bodies);
        }
    }
}
