use super::*;

#[test]
fn fixed_queries_are_bounded_and_current_database_scoped() {
    assert_eq!(SqlServerReadProbe::ALL.len(), 8);
    for probe in SqlServerReadProbe::ALL {
        let sql = probe.sql();
        assert!(!sql.contains("SELECT *"));
        if probe != SqlServerReadProbe::Identity {
            assert!(sql.contains("TOP ("));
        }
        if matches!(
            probe,
            SqlServerReadProbe::Requests | SqlServerReadProbe::Waits | SqlServerReadProbe::Blocking
        ) {
            assert!(sql.contains("DB_ID()"));
        }
        if probe.needs_object() {
            assert!(sql.contains("@P1") && sql.contains("@P2"));
        }
    }
    assert_eq!(template_digest().len(), 64);
}

#[test]
fn sql_server_tokens_do_not_masquerade_as_postgres_tokens() {
    assert!(SqlObservation::tds_state("suspended"));
    assert!(!SqlObservation::pg_state("suspended"));
    assert!(SqlObservation::version_token("16.0.1000.6"));
    assert!(!SqlObservation::version_token("PostgreSQL 16"));
    let identity = SqlObservation::SqlServerIdentity {
        database: "fixture".into(),
        principal: "reader".into(),
        product_version: "16.0.1000.6".into(),
        server_ip: "127.0.0.1".into(),
        server_port: 1433,
        tls_required: true,
        server_state_access: Some(false),
        server_performance_access: None,
    };
    assert!(identity.bounded());
}

#[test]
fn denied_visibility_and_nulls_never_become_healthy() {
    assert_eq!(
        classify(
            SqlServerReadProbe::Requests,
            &[SqlObservation::SqlServerRequest {
                session_id: 42,
                state: None,
                wait_type: None,
                elapsed_ms: None
            }]
        ),
        ReadState::Unknown
    );
    assert_eq!(
        classify(
            SqlServerReadProbe::Permissions,
            &[SqlObservation::SqlServerPermission {
                database_connect: Some(false),
                schema_select: None,
                object_select: None,
                object_alter: None,
                object_control: None
            }]
        ),
        ReadState::Denied
    );
    assert_eq!(
        classify(SqlServerReadProbe::Objects, &[]),
        ReadState::Unknown
    );
    assert!(
        !SqlObservation::SqlServerRequest {
            session_id: 0,
            state: Some("running".into()),
            wait_type: None,
            elapsed_ms: Some(1),
        }
        .bounded()
    );
}

#[test]
fn identity_must_match_database_login_endpoint_and_tls() {
    let mut value = SqlObservation::SqlServerIdentity {
        database: "fixture".into(),
        principal: "reader".into(),
        product_version: "16.0.1000.6".into(),
        server_ip: "127.0.0.1".into(),
        server_port: 1433,
        tls_required: true,
        server_state_access: Some(true),
        server_performance_access: None,
    };
    assert_eq!(
        verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1433).unwrap(),
        true
    );
    if let SqlObservation::SqlServerIdentity {
        server_state_access,
        ..
    } = &mut value
    {
        *server_state_access = Some(false);
    }
    assert!(!verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1433).unwrap());
    assert!(verify_identity(&[value.clone()], "other", "reader", "127.0.0.1", 1433).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "other", "127.0.0.1", 1433).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.1", 1444).is_err());
    assert!(verify_identity(&[value.clone()], "fixture", "reader", "127.0.0.2", 1433).is_err());
    if let SqlObservation::SqlServerIdentity { tls_required, .. } = &mut value {
        *tls_required = false;
    }
    assert!(verify_identity(&[value], "fixture", "reader", "127.0.0.1", 1433).is_err());
}

#[test]
fn cancellation_and_deadline_interrupt_stalled_tds_operations() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        let canceled = CancellationToken::new();
        canceled.cancel();
        let stalled: TdsFuture<'_, ()> = Box::pin(std::future::pending());
        assert_eq!(
            gated(&canceled, Instant::now() + Duration::from_secs(1), stalled).await,
            Err(Failure::Canceled)
        );
        let stalled: TdsFuture<'_, ()> = Box::pin(std::future::pending());
        assert_eq!(
            gated(&CancellationToken::new(), Instant::now(), stalled).await,
            Err(Failure::TimedOut)
        );
    });
}
