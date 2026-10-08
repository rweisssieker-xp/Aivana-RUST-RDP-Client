-- Synthetic Windows Sandbox data only. Run once against the dedicated cluster.
DO $guard$
BEGIN
    IF current_database() <> 'relayne_helper_acceptance'
       OR current_user <> 'relayne_fixture_owner'
       OR current_setting('port') <> '55433'
       OR inet_server_addr() IS DISTINCT FROM inet '127.0.0.1' THEN
        RAISE EXCEPTION 'Refusing fixture seed outside the dedicated guest database, role, port, and loopback listener (database=%, role=%, port=%, server_address=%)',
            current_database(), current_user, current_setting('port'), inet_server_addr();
    END IF;
END
$guard$;

CREATE SCHEMA fixture AUTHORIZATION relayne_fixture_owner;

-- customer_id deliberately has no index. A lookup for one customer scans this
-- larger table, providing a real plan for an exact reviewed index proposal.
CREATE TABLE fixture.orders (
    order_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id integer NOT NULL,
    status text NOT NULL,
    amount numeric(12,2) NOT NULL,
    created_at timestamptz NOT NULL,
    detail text NOT NULL
);
INSERT INTO fixture.orders (customer_id, status, amount, created_at, detail)
SELECT (g % 2000) + 1,
       CASE WHEN g % 13 = 0 THEN 'pending' ELSE 'fulfilled' END,
       ((g % 791) + 10)::numeric / 10,
       timestamptz '2025-01-01 00:00:00+00' + (g * interval '1 minute'),
       repeat(md5(g::text), 3)
FROM generate_series(1, 60000) AS g;

-- Capture baseline statistics, then add a strong unanalysed skew. The estimate
-- can be compared with actual rows; acceptance must still measure and verify it.
ANALYZE fixture.orders;
ALTER TABLE fixture.orders SET (autovacuum_enabled = false);
INSERT INTO fixture.orders (customer_id, status, amount, created_at, detail)
SELECT 424242, 'pending', 99.99,
       timestamptz '2025-03-01 00:00:00+00' + (g * interval '1 second'),
       repeat(md5(('skew-' || g)::text), 3)
FROM generate_series(1, 15000) AS g;

-- Sorting the payload under a deliberately small work_mem can produce temp I/O.
-- Operators must verify actual spill evidence; these rows alone are not proof.
CREATE TABLE fixture.spill_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id integer NOT NULL,
    payload text NOT NULL
);
INSERT INTO fixture.spill_events (group_id, payload)
SELECT g % 100, repeat(md5(('spill-' || g)::text), 16)
FROM generate_series(1, 12000) AS g;
ANALYZE fixture.spill_events;

-- A blocked session needs two live connections. The README gives the two
-- transaction statements; bootstrap does not hold a lock indefinitely.
CREATE TABLE fixture.blocker_rows (
    row_id integer PRIMARY KEY,
    owner_label text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO fixture.blocker_rows (row_id, owner_label) VALUES
    (1, 'synthetic blocker target'),
    (2, 'synthetic control row');
ANALYZE fixture.blocker_rows;
