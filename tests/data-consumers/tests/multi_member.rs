//! Synthetic multi-member/audience fixture: assumed authenticated scopes,
//! not invitations/roles/key distribution. This tests the production data/session
//! boundary, not account authentication, runner grants or audience key delivery.
use bh_data::{
    Actor, AppId, CoreCatalogue, DataError, KeyRef, RevisionId, Scope,
    catalogue::Shipped,
    index,
    mutation::{apply::Outcome, ops::Operation},
    query::{Aggregate, Completeness, Expr, Measure, QueryError, TextMatch, TypeSelect},
    session::{DataSession, SessionError, Store},
    testkit::{Delivery, OrderedLog, Replica},
};
use bh_data_consumers::{
    Bodies, SHARED, all, article, authority, path, project, reference, rid, selection, session, set,
};
use bh_data_fixtures::{job, member};
use rusqlite::{Connection, OpenFlags, Transaction};
use serde_json::json;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

const ADA: Scope = Scope {
    audience: [11; 32],
    ..SHARED
};
const BEN: Scope = Scope {
    audience: [12; 32],
    ..SHARED
};
const ELSEWHERE: Scope = Scope {
    base: [9; 32],
    audience: [0; 32],
};

fn order(replica: &mut Replica, log: &mut OrderedLog, scope: Scope, actor: Actor, op: Operation) {
    let saved = session(replica, scope, actor.clone()).submit(op).unwrap();
    log.append(scope, &actor, saved.payload);
    let outcomes = replica.sync_from(log, Delivery::InOrder).unwrap();
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| matches!(o, Outcome::Accepted { .. })),
        "{outcomes:?}"
    );
}
fn install(replica: &mut Replica, log: &mut OrderedLog, scope: Scope) {
    for op in [
        Operation::DefineApp {
            app: article::APP,
            name: "Article reader".into(),
        },
        Operation::DefineApp {
            app: selection::APP,
            name: "Source selection".into(),
        },
        Operation::DefineType {
            bytes: article::DEFINITION.to_vec(),
        },
        Operation::DefineType {
            bytes: selection::DEFINITION.to_vec(),
        },
    ] {
        order(replica, log, scope, member(1), op);
    }
}
fn create(replica: &mut Replica, log: &mut OrderedLog, scope: Scope, id: u8, title: &str) {
    let saved = article::save(
        &session(replica, scope, member(1)),
        rid(id),
        title,
        &format!("https://example.test/{id}"),
        1_700_000_000_000,
        reference(rid(10)),
    )
    .unwrap();
    log.append(scope, &member(1), saved.payload);
    let outcomes = replica.sync_from(log, Delivery::InOrder).unwrap();
    assert!(
        outcomes
            .iter()
            .all(|(_, o)| matches!(o, Outcome::Accepted { .. })),
        "{outcomes:?}"
    );
}
fn denied(
    result: Result<bh_data::mutation::pending::LocalSaved, SessionError>,
    code: bh_data::RejectCode,
) {
    assert!(
        matches!(result,Err(SessionError::Rejected(ref r)) if r.code==code),
        "{result:?}"
    );
}

#[test]
fn three_members_see_only_their_scopes_in_rows_counts_text_and_backlinks() {
    let mut replica = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    let mut bodies = Bodies::default();
    for (scope, title, n) in [
        (SHARED, "Solar shared", 1),
        (ADA, "Ada secret", 2),
        (BEN, "Ben secret", 3),
        (ELSEWHERE, "Other base", 4),
    ] {
        install(&mut replica, &mut log, scope);
        bodies.0.insert((scope, rid(10)), format!("{title} body"));
        project(&replica, scope, rid(10), title, &bodies);
        create(&mut replica, &mut log, scope, 1, title);
        // Private selections refer to the same shared Article. Their reasons and
        // existence must not be included in shared backlinks or counts.
        for id in 30..30 + n {
            let target = bh_data::RecordRef {
                audience: Some([0; 32]),
                record: rid(1),
            };
            let saved = selection::select(
                &session(&replica, scope, member(1)),
                rid(id),
                target,
                reference(rid(20)),
                title,
                reference(rid(10)),
            )
            .unwrap();
            log.append(scope, &member(1), saved.payload);
            let outcomes = replica.sync_from(&log, Delivery::InOrder).unwrap();
            assert!(
                outcomes
                    .iter()
                    .all(|(_, o)| matches!(o, Outcome::Accepted { .. }))
            );
        }
    }
    for (actor, reads, private, private_count) in [
        (member(1), vec![SHARED, ADA], Some(ADA), 2),
        (member(2), vec![SHARED, BEN], Some(BEN), 3),
        (member(3), vec![SHARED], None, 0),
    ] {
        let s = DataSession::new(&replica, authority(actor, reads.clone(), Some(SHARED)));
        let mut q = all(selection::type_id());
        q.fields = vec![path("/reason")];
        q.filter = Some(Expr::RefersTo {
            path: path("/article"),
            target: reference(rid(1)),
        });
        let page = s.query(SHARED, &q).unwrap();
        assert_eq!(page.completeness, Completeness::Complete);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].values["/reason"], "Solar shared");
        let count = Aggregate {
            select: TypeSelect::Exact(selection::type_id()),
            filter: q.filter.clone(),
            group_by: None,
            measures: vec![Measure::Count],
            max_groups: 10,
        };
        assert_eq!(
            s.aggregate(SHARED, &count).unwrap().groups[0].values,
            vec![json!(1)]
        );
        q.text = Some(TextMatch {
            terms: "secret".into(),
            on: None,
            require_revision: None,
        });
        assert!(s.query(SHARED, &q).unwrap().rows.is_empty());
        if let Some(private) = private {
            q.text = None;
            q.filter = Some(Expr::RefersTo {
                path: path("/article"),
                target: bh_data::RecordRef {
                    audience: Some([0; 32]),
                    record: rid(1),
                },
            });
            assert_eq!(s.query(private, &q).unwrap().rows.len(), private_count);
            let count = Aggregate {
                filter: q.filter.clone(),
                ..count.clone()
            };
            assert_eq!(
                s.aggregate(private, &count).unwrap().groups[0].values,
                vec![json!(private_count)]
            );
            assert_ne!(
                s.get(private, rid(1)).unwrap().unwrap().accepted.unwrap()["title"],
                "Solar shared"
            );
        }
        for forbidden in [ADA, BEN, ELSEWHERE]
            .into_iter()
            .filter(|scope| !reads.contains(scope))
        {
            assert_eq!(s.query(forbidden, &q), Err(QueryError::Unauthorized));
            assert_eq!(
                s.aggregate(forbidden, &count),
                Err(QueryError::Unauthorized)
            );
            assert!(matches!(
                s.get(forbidden, rid(1)),
                Err(DataError::Unauthorized)
            ));
            assert!(matches!(
                s.list_types(forbidden),
                Err(DataError::Unauthorized)
            ));
        }
    }
}

#[test]
fn direct_action_only_and_derived_matrix_for_devices_and_jobs() {
    let mut replica = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    install(&mut replica, &mut log, SHARED);
    let mut bodies = Bodies::default();
    bodies.0.insert((SHARED, rid(10)), "Canonical body".into());
    project(&replica, SHARED, rid(10), "Canonical title", &bodies);
    create(&mut replica, &mut log, SHARED, 1, "Solar shared");
    for actor in [
        member(1),
        member(2),
        member(3),
        job(1, None),
        job(2, Some("archive")),
        job(3, Some("other")),
    ] {
        // Direct is writable by both devices and jobs with write scope.
        order(
            &mut replica,
            &mut log,
            SHARED,
            actor.clone(),
            Operation::Edit {
                record: rid(1),
                revision: RevisionId::of(article::DEFINITION),
                changes: vec![set("/state", json!("saved"))],
            },
        );
        let s = session(&replica, SHARED, actor.clone());
        denied(
            s.submit(Operation::Edit {
                record: rid(1),
                revision: RevisionId::of(article::DEFINITION),
                changes: vec![set("/archived", json!(true))],
            }),
            bh_data::RejectCode::ActionOnly,
        );
        denied(
            s.submit(Operation::Edit {
                record: rid(10),
                revision: bh_data::catalogue::baseline_note().1,
                changes: vec![set("/title", json!("Forbidden copy"))],
            }),
            bh_data::RejectCode::DerivedField,
        );
        let action = Operation::Action {
            record: rid(1),
            app: AppId([2; 32]),
            action: "archive".into(),
            changes: vec![set("/archived", json!(true))],
        };
        if actor == job(2, Some("archive")) {
            order(&mut replica, &mut log, SHARED, actor, action);
        } else {
            denied(s.submit(action), bh_data::RejectCode::ActionOnly);
        }
    }
    let s = session(&replica, SHARED, member(3));
    assert_eq!(
        s.get(SHARED, rid(1)).unwrap().unwrap().accepted.unwrap()["archived"],
        true
    );
    assert_eq!(
        s.get(SHARED, rid(10)).unwrap().unwrap().accepted.unwrap(),
        json!({"title":"Canonical title"})
    );
    let read_only = DataSession::new(&replica, authority(member(3), vec![SHARED], None));
    denied(
        read_only.submit(Operation::Delete { record: rid(1) }),
        bh_data::RejectCode::Unauthorized,
    );
}

/// A real read-only SQLite connection feeding the production session.
struct Reader(Connection);
impl Store for Reader {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        f(&self.0)
    }
    fn write<R>(
        &self,
        _f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        Err(DataError::Unauthorized)
    }
    fn core(&self) -> &dyn CoreCatalogue {
        &Shipped
    }
}
/// Holds a real writer transaction open after its changes. Readers must answer
/// before commit; a serial reader/writer implementation times out instead of passing.
struct PausedWriter<'a> {
    replica: &'a Replica,
    phase: usize,
    notices: &'a [Sender<usize>],
    completed: &'a Receiver<()>,
}
impl Store for PausedWriter<'_> {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        self.replica.read(f)
    }
    fn write<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        self.replica.write(|tx| {
            let value = f(tx)?;
            assert!(!tx.is_autocommit());
            for notice in self.notices {
                notice.send(self.phase).unwrap();
            }
            for _ in self.notices {
                self.completed
                    .recv_timeout(Duration::from_secs(10))
                    .expect("reader blocked behind a writer/backfill");
            }
            Ok(value)
        })
    }
    fn core(&self) -> &dyn CoreCatalogue {
        &Shipped
    }
}

#[test]
fn independent_read_connections_answer_during_writes_and_index_backfill() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("readers.sqlite");
    let mut replica = Replica::new_file(&db).unwrap();
    replica
        .conn()
        .execute_batch("PRAGMA journal_mode=WAL")
        .unwrap();
    let mut log = OrderedLog::new();
    install(&mut replica, &mut log, SHARED);
    install(&mut replica, &mut log, ELSEWHERE);
    for n in 1..=64 {
        create(&mut replica, &mut log, SHARED, n, "Solar shared");
    }
    create(
        &mut replica,
        &mut log,
        ELSEWHERE,
        1,
        "Other base keeps answering",
    );
    replica.hold_backfill();

    let (complete_tx, complete_rx) = mpsc::channel();
    let mut notices = Vec::new();
    let mut threads = Vec::new();
    for (actor, scope, want) in [
        (member(1), SHARED, 50),
        (member(2), SHARED, 50),
        (member(3), ELSEWHERE, 1),
    ] {
        let (tx, rx) = mpsc::channel();
        notices.push(tx);
        let done = complete_tx.clone();
        let db = db.clone();
        threads.push(std::thread::spawn(move || {
            let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            conn.busy_timeout(Duration::from_secs(2)).unwrap();
            let s = DataSession::new(Reader(conn), authority(actor, vec![scope], None));
            let mut answered = 0;
            while let Ok(phase) = rx.recv_timeout(Duration::from_secs(10)) {
                let page = s.query(scope, &all(article::type_id())).unwrap();
                assert_eq!(page.rows.len(), want);
                assert_eq!(page.completeness, Completeness::Complete);
                let row = s.get(scope, rid(1)).unwrap().unwrap();
                let record = row.doc.or(row.accepted).unwrap();
                if scope == ELSEWHERE {
                    assert_eq!(record["title"], "Other base keeps answering");
                } else {
                    assert_eq!(
                        record["title"],
                        if phase == 0 {
                            "Solar shared"
                        } else {
                            "Solar edited"
                        }
                    );
                }
                answered += 1;
                done.send(()).unwrap();
            }
            answered
        }));
    }
    // Phase 0: actual session edit, uncommitted while all three readers answer.
    let writer = PausedWriter {
        replica: &replica,
        phase: 0,
        notices: &notices,
        completed: &complete_rx,
    };
    let s = DataSession::new(writer, authority(member(1), vec![SHARED], Some(SHARED)));
    let saved = article::edit(
        &s,
        rid(1),
        RevisionId::of(article::DEFINITION),
        vec![set("/title", json!("Solar edited"))],
    )
    .unwrap();
    log.append(SHARED, &member(1), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();

    // New schema/index in this base; unrelated base has no schema adoption.
    let mut v2: serde_json::Value = serde_json::from_slice(article::DEFINITION).unwrap();
    v2["evolution"]["previous"] = json!(RevisionId::of(article::DEFINITION));
    v2["indexes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"by_state","keys":["/state"]}));
    order(
        &mut replica,
        &mut log,
        SHARED,
        member(1),
        Operation::DefineType {
            bytes: serde_json::to_vec(&v2).unwrap(),
        },
    );
    let ix = index::pending_work(replica.conn())
        .unwrap()
        .into_iter()
        .find(|id| {
            let state = index::state(replica.conn(), *id).unwrap();
            state.family == article::type_id() && state.keys == vec![KeyRef::Field(path("/state"))]
        })
        .unwrap();
    assert_eq!(index::state(replica.conn(), ix).unwrap().built, 0);
    // Phase 1: real backfill modifies index rows within an open transaction.
    let writer = PausedWriter {
        replica: &replica,
        phase: 1,
        notices: &notices,
        completed: &complete_rx,
    };
    let progress = writer.write(|tx| index::backfill_step(tx, ix, 16)).unwrap();
    assert!(!progress.ready);
    assert_eq!(index::state(replica.conn(), ix).unwrap().built, 16);
    // Phase 2: ordinary write while that index is still only partially built.
    let writer = PausedWriter {
        replica: &replica,
        phase: 2,
        notices: &notices,
        completed: &complete_rx,
    };
    let s = DataSession::new(writer, authority(member(2), vec![SHARED], Some(SHARED)));
    let saved = article::edit(
        &s,
        rid(64),
        RevisionId::of(article::DEFINITION),
        vec![set("/state", json!("saved"))],
    )
    .unwrap();
    log.append(SHARED, &member(2), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    drop(notices);
    for thread in threads {
        assert_eq!(thread.join().unwrap(), 3);
    }
    replica.release_backfill().unwrap();
    assert_eq!(index::state(replica.conn(), ix).unwrap().state, "ready");
    let mut q = all(article::type_id());
    q.filter = Some(Expr::Cmp {
        path: path("/state"),
        op: bh_data::query::CmpOp::Eq,
        value: json!("saved"),
    });
    let page = session(&replica, SHARED, member(3))
        .query(SHARED, &q)
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].record, rid(64));
    assert_eq!(page.completeness, Completeness::Complete);
}
