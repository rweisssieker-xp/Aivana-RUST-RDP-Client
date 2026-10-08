-- psql -f expands only the validated, typed variables supplied by app-service.ps1.
-- This query is fixed and bounded. No HTTP text is concatenated into SQL.
SELECT json_build_object(
    'database', current_database(),
    'role', current_user,
    'customer_id', :'customer_id'::integer,
    'orders', COALESCE((
        SELECT json_agg(row_to_json(o) ORDER BY o.order_id)
        FROM (
            SELECT order_id, customer_id, status, amount
            FROM fixture.orders
            WHERE customer_id = :'customer_id'::integer
            ORDER BY order_id
            LIMIT :'row_limit'::integer
        ) AS o
    ), '[]'::json)
)::text;
