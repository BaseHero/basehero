use bh_data::{
    Actor, DataError, RecordId, RejectCode, Scope, TypeId,
    catalogue::Shipped,
    mutation::ops::Operation,
    query::{Aggregate, Measure, Query, QueryError, TypeSelect},
    session::{Authority, DataSession, SessionError, Store},
    testkit::Replica,
    tools,
};
use rusqlite::{Connection, Transaction};
use serde_json::json;

struct LocalAuthority {
    scope: Scope,
    writable: bool,
}
impl Authority for LocalAuthority {
    fn actor(&self) -> Actor {
        Actor::Device {
            account: [1; 32],
            device: [2; 32],
        }
    }
    fn reads(&self) -> Vec<Scope> {
        vec![self.scope]
    }
    fn write(&self) -> Option<Scope> {
        self.writable.then_some(self.scope)
    }
}

#[test]
fn caller_selected_scope_cannot_bypass_verified_read_or_write_authority() {
    let store = Replica::new_in_memory().unwrap();
    let allowed = Scope {
        base: [3; 32],
        audience: [4; 32],
    };
    let denied = Scope {
        base: [3; 32],
        audience: [5; 32],
    };
    let session = DataSession::new(
        &store,
        LocalAuthority {
            scope: allowed,
            writable: false,
        },
    );
    let query = Query {
        select: TypeSelect::Exact(TypeId::core("note")),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    let aggregate = Aggregate {
        select: TypeSelect::Exact(TypeId::core("note")),
        filter: None,
        group_by: None,
        measures: vec![Measure::Count],
        max_groups: 10,
    };
    let record = RecordId([6; 32]);
    assert_eq!(
        session.query(denied, &query).unwrap_err(),
        QueryError::Unauthorized
    );
    assert_eq!(
        session.aggregate(denied, &aggregate).unwrap_err(),
        QueryError::Unauthorized
    );
    assert!(matches!(
        session.get(denied, record),
        Err(DataError::Unauthorized)
    ));
    assert!(matches!(
        session.history(denied, record, None, 50),
        Err(DataError::Unauthorized)
    ));
    assert!(session.get(allowed, record).unwrap().is_none());
    assert!(
        matches!(session.submit(Operation::Delete { record }), Err(SessionError::Rejected(r)) if r.code == RejectCode::Unauthorized)
    );
}

#[test]
fn device_tool_rule_change_requires_exact_host_confirmation() {
    use bh_data::{
        MutationId, payload,
        testkit::{Delivery, OrderedLog},
    };
    let scope = Scope {
        base: [3; 32],
        audience: [0; 32],
    };
    let mut store = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    let authority = LocalAuthority {
        scope,
        writable: true,
    };
    let mut doc: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/types/Article.json")).unwrap();
    for op in [
        Operation::DefineApp {
            app: bh_data::AppId([2; 32]),
            name: "Article".into(),
        },
        Operation::DefineType {
            bytes: serde_json::to_vec(&doc).unwrap(),
        },
    ] {
        log.append(
            scope,
            &authority.actor(),
            payload::encode(MutationId::random(), &op).unwrap(),
        );
        store.sync_from(&log, Delivery::InOrder).unwrap();
    }
    doc["unique"] = json!([]);
    let op = Operation::DefineType {
        bytes: serde_json::to_vec(&doc).unwrap(),
    };
    let session = DataSession::new(&store, authority);
    let result = tools::call(
        &session,
        "records.mutate",
        serde_json::to_value(&op).unwrap(),
    );
    assert!(result.get("proposal").is_some(), "{result}");
    assert!(
        session
            .approve(
                session
                    .prepare_change(match &op {
                        Operation::DefineType { bytes } => bytes,
                        _ => unreachable!(),
                    })
                    .unwrap()
            )
            .is_err()
    );
    let pending: i64 = store
        .conn()
        .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(pending, 0);
    let request = match session.submit(op.clone()) {
        Err(SessionError::ConfirmationRequired(p)) => *p,
        other => panic!("{other:?}"),
    };
    // Exact fixture evidence is not a device-wide approval or a tool flag.
    for altered in 0..3 {
        let mut evidence = request.clone();
        match altered {
            0 => evidence.scope.audience = [9; 32],
            1 => {
                evidence.operation = Operation::SetAppState {
                    app: bh_data::AppId([2; 32]),
                    active: false,
                }
            }
            _ => {
                evidence.prior = bh_data::admission::PriorRules::Type {
                    revision: None,
                    permitted: vec![],
                }
            }
        }
        let exact = DataSession::new(&store, ExactAuthority { scope, evidence });
        assert!(matches!(
            exact.submit(op.clone()),
            Err(SessionError::ConfirmationRequired(_))
        ));
    }
    let exact = DataSession::new(
        &store,
        ExactAuthority {
            scope,
            evidence: request,
        },
    );
    let proposal = exact
        .prepare_change(match &op {
            Operation::DefineType { bytes } => bytes,
            _ => unreachable!(),
        })
        .unwrap();
    assert!(exact.approve(proposal).is_ok());
}
struct ExactAuthority {
    scope: Scope,
    evidence: bh_data::admission::Confirmation,
}
impl Authority for ExactAuthority {
    fn actor(&self) -> Actor {
        Actor::Device {
            account: [1; 32],
            device: [2; 32],
        }
    }
    fn reads(&self) -> Vec<Scope> {
        vec![self.scope]
    }
    fn write(&self) -> Option<Scope> {
        Some(self.scope)
    }
    fn confirm_rule_change(
        &self,
        request: &bh_data::admission::Confirmation,
        _at: Option<bh_data::Position>,
    ) -> Result<bool, DataError> {
        Ok(*request == self.evidence)
    }
}
struct FailingStore(Replica);
impl Store for FailingStore {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        f(self.0.conn())
    }
    fn write<R>(
        &self,
        _f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        Err(DataError::Corrupt("injected write failure".into()))
    }
    fn core(&self) -> &dyn bh_data::CoreCatalogue {
        &Shipped
    }
}

#[test]
fn storage_failure_is_not_a_schema_rejection_in_session_or_tools() {
    let scope = Scope {
        base: [3; 32],
        audience: [4; 32],
    };
    let store = FailingStore(Replica::new_in_memory().unwrap());
    let session = DataSession::new(
        &store,
        LocalAuthority {
            scope,
            writable: true,
        },
    );
    let op = Operation::DefineApp {
        app: bh_data::AppId([2; 32]),
        name: "Articles".into(),
    };
    assert!(matches!(
        session.submit(op.clone()),
        Err(SessionError::Data(DataError::Corrupt(_)))
    ));
    assert!(matches!(
        session.validate(&op),
        Err(SessionError::Data(DataError::Corrupt(_)))
    ));
    assert_eq!(
        tools::call(
            &session,
            "records.mutate",
            serde_json::to_value(&op).unwrap()
        )["error"]["code"],
        "Corrupt"
    );
    assert_eq!(
        tools::call(
            &session,
            "records.validate",
            serde_json::to_value(&op).unwrap()
        )["error"]["code"],
        "Corrupt"
    );
    // The tool must not mislabel a failed write as a malformed operation.
    assert_ne!(
        tools::call(
            &session,
            "records.mutate",
            serde_json::to_value(op).unwrap()
        )["error"]["code"],
        json!("Schema")
    );
}
