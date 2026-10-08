//! Bounded, redacted plan projections. Imported plans are never execution evidence.
use anyhow::{Result, bail, ensure};
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const MAX_PLAN_BYTES: usize = 1024 * 1024;
pub const MAX_PLAN_DEPTH: usize = 64;
pub const MAX_PLAN_NODES: usize = 4096;

struct RawPlanJson(Vec<u8>);
impl<'a> tokio_postgres::types::FromSql<'a> for RawPlanJson {
    fn from_sql(
        _ty: &tokio_postgres::types::Type,
        raw: &'a [u8],
    ) -> std::result::Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if raw.len() > MAX_PLAN_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native plan exceeds input limit",
            )
            .into());
        }
        Ok(Self(raw.to_vec()))
    }
    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        *ty == tokio_postgres::types::Type::JSON
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanImportFormat {
    PostgresJson,
    PsqlAlignedExplainJson,
    SqlServerShowplanXml,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportSource {
    OperatorFile,
    ExternalExport,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanOrigin {
    ImportedUnverified,
    LiveEstimate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spill {
    DiskSort,
    SqlServerSpill,
}
#[derive(Clone, Debug)]
pub struct PlanNode {
    pub operator: &'static str,
    pub estimated_rows: Option<f64>,
    pub actual_rows: Option<f64>,
    pub actual_executions: Option<f64>,
    pub estimated_cost: Option<f64>,
    pub actual_ms: Option<f64>,
    pub spill: Option<Spill>,
    pub temp_io: bool,
    pub children: Vec<PlanNode>,
}
#[derive(Clone, Debug)]
pub struct PlanReport {
    origin: PlanOrigin,
    pub format: PlanImportFormat,
    pub source: Option<ImportSource>,
    pub source_sha256: String,
    live_metadata_sha256: Option<String>,
    pub roots: Vec<PlanNode>,
    pub has_actuals: bool,
    pub has_spill_evidence: bool,
    pub has_temp_io: bool,
    pub limitations: Vec<&'static str>,
}
impl PlanReport {
    pub(crate) fn with_live_metadata(mut self, digest: String) -> Result<Self> {
        ensure!(
            self.origin == PlanOrigin::LiveEstimate && crate::helper::evidence::is_digest(&digest),
            "live plan metadata digest missing"
        );
        self.live_metadata_sha256 = Some(digest);
        Ok(self)
    }
    pub fn origin(&self) -> PlanOrigin {
        self.origin
    }
    pub fn live_metadata_sha256(&self) -> Option<&str> {
        self.live_metadata_sha256.as_deref()
    }
    /// Only a separately authorized live observation may be considered for live proof.
    pub fn can_prove_live(&self) -> bool {
        self.origin == PlanOrigin::LiveEstimate && self.live_metadata_sha256.is_some()
    }
    pub fn can_prove_execution(&self) -> bool {
        false
    }
    pub fn operators(&self) -> usize {
        fn count(n: &PlanNode) -> usize {
            1 + n.children.iter().map(count).sum::<usize>()
        }
        self.roots.iter().map(count).sum()
    }
}

pub fn parse_import(
    format: PlanImportFormat,
    bytes: &[u8],
    source: ImportSource,
) -> Result<PlanReport> {
    let mut report = parse(format, bytes)?;
    report.origin = PlanOrigin::ImportedUnverified;
    report.source = Some(source);
    report
        .limitations
        .push("Imported collection context is unverified; this is not live proof.");
    Ok(report)
}

pub(crate) fn parse_live_estimate(format: PlanImportFormat, bytes: &[u8]) -> Result<PlanReport> {
    ensure!(
        format != PlanImportFormat::PsqlAlignedExplainJson,
        "live transport must return a native plan"
    );
    let mut report = parse(format, bytes)?;
    ensure!(
        !report.has_actuals,
        "estimate collection returned execution counters"
    );
    report.origin = PlanOrigin::LiveEstimate;
    report
        .limitations
        .push("Estimated plan costs are advisory and do not measure runtime.");
    Ok(report)
}

fn parse(format: PlanImportFormat, bytes: &[u8]) -> Result<PlanReport> {
    ensure!(bytes.len() <= MAX_PLAN_BYTES, "plan input too large");
    let input = decode(bytes)?;
    let roots = match format {
        PlanImportFormat::PostgresJson => parse_pg(&input)?,
        PlanImportFormat::PsqlAlignedExplainJson => parse_pg(&unwrap_psql(&input)?)?,
        PlanImportFormat::SqlServerShowplanXml => parse_xml(&input)?,
    };
    ensure!(!roots.is_empty(), "plan has no operators");
    let mut count = 0;
    let mut actual = false;
    let mut spill = false;
    let mut temp_io = false;
    fn inspect(
        n: &PlanNode,
        depth: usize,
        count: &mut usize,
        actual: &mut bool,
        spill: &mut bool,
        temp_io: &mut bool,
    ) -> Result<()> {
        ensure!(depth <= MAX_PLAN_DEPTH, "plan operator depth exceeded");
        *count += 1;
        ensure!(*count <= MAX_PLAN_NODES, "plan operator count exceeded");
        *actual |=
            n.actual_rows.is_some() || n.actual_executions.is_some() || n.actual_ms.is_some();
        *spill |= n.spill.is_some();
        *temp_io |= n.temp_io;
        for c in &n.children {
            inspect(c, depth + 1, count, actual, spill, temp_io)?;
        }
        Ok(())
    }
    for root in &roots {
        inspect(root, 1, &mut count, &mut actual, &mut spill, &mut temp_io)?;
    }
    Ok(PlanReport {
        origin: PlanOrigin::ImportedUnverified,
        format,
        source: None,
        source_sha256: format!("{:x}", Sha256::digest(bytes)),
        roots,
        live_metadata_sha256: None,
        has_actuals: actual,
        has_spill_evidence: spill,
        has_temp_io: temp_io,
        limitations: vec![
            "Missing runtime counters or spill warnings do not prove their absence.",
            match format {
                PlanImportFormat::SqlServerShowplanXml => {
                    "SQL Server per-thread counters are summed; elapsed sums are not wall-clock time."
                }
                _ => "PostgreSQL Actual Rows and Actual Total Time are reported per loop.",
            },
        ],
    })
}

fn decode(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Ok(std::str::from_utf8(&bytes[3..])?.to_owned());
    }
    let utf16 = if bytes.starts_with(&[0xff, 0xfe]) {
        Some((true, &bytes[2..]))
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Some((false, &bytes[2..]))
    } else {
        None
    };
    if let Some((little, body)) = utf16 {
        ensure!(body.len() % 2 == 0, "odd UTF-16 byte count");
        let units = body.chunks_exact(2).map(|pair| {
            if little {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        });
        return Ok(std::char::decode_utf16(units).collect::<std::result::Result<String, _>>()?);
    }
    Ok(std::str::from_utf8(bytes)?.to_owned())
}

fn unwrap_psql(input: &str) -> Result<String> {
    enum State {
        Preamble,
        Body,
        Tail,
    }
    let mut state = State::Preamble;
    let mut aligned = false;
    let mut lines = Vec::new();
    let mut has_header = false;
    let mut nesting = 0i32;
    let mut footer_seen = false;
    for raw in input.lines() {
        let line = raw.trim();
        match state {
            State::Preamble => {
                if line.is_empty() || line == "SET" {
                    continue;
                }
                if line == "QUERY PLAN" && !has_header {
                    has_header = true;
                    aligned = true;
                    continue;
                }
                if has_header && line.len() >= 3 && line.bytes().all(|b| b == b'-') {
                    continue;
                }
                let first = if aligned {
                    line.strip_suffix('+').map(str::trim_end).unwrap_or(line)
                } else {
                    line
                };
                ensure!(first == "[", "invalid psql plan preamble");
                lines.push(first.to_owned());
                nesting = 1;
                state = State::Body;
            }
            State::Body => {
                let normalized = if aligned {
                    line.strip_suffix('+').map(str::trim_end).unwrap_or(line)
                } else {
                    line
                };
                ensure!(!normalized.is_empty(), "empty psql plan row");
                lines.push(normalized.to_owned());
                nesting += json_line_delta(normalized);
                ensure!(nesting >= 0, "invalid psql JSON nesting");
                if nesting == 0 {
                    state = State::Tail;
                }
            }
            State::Tail => {
                if line.is_empty() {
                    continue;
                }
                let footer = line
                    .strip_prefix('(')
                    .and_then(|s| s.strip_suffix(')'))
                    .and_then(|s| s.split_once(' '))
                    .is_some_and(|(count, word)| {
                        count == "1" && matches!(word, "row" | "rows" | "Zeile" | "Zeilen")
                    });
                ensure!(aligned && footer && !footer_seen, "extra psql output");
                footer_seen = true;
            }
        }
    }
    ensure!(matches!(state, State::Tail), "incomplete psql plan");
    ensure!(!aligned || footer_seen, "aligned psql footer missing");
    Ok(lines.join("\n"))
}

fn json_line_delta(line: &str) -> i32 {
    let mut delta = 0;
    let mut quoted = false;
    let mut escaped = false;
    for byte in line.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => delta += 1,
                b']' | b'}' => delta -= 1,
                _ => {}
            }
        }
    }
    delta
}

fn structural_json_limits(input: &str) -> Result<()> {
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    nodes += 1;
                    ensure!(
                        depth <= MAX_PLAN_DEPTH && nodes <= MAX_PLAN_NODES,
                        "JSON depth/node limit exceeded"
                    );
                }
                b']' | b'}' => {
                    ensure!(depth > 0, "invalid JSON structure");
                    depth -= 1;
                }
                _ => {}
            }
        }
    }
    ensure!(!quoted && depth == 0, "invalid JSON structure");
    reject_duplicate_json_keys(input)?;
    Ok(())
}

fn reject_duplicate_json_keys(input: &str) -> Result<()> {
    let bytes = input.as_bytes();
    let mut stack: Vec<Option<HashSet<String>>> = Vec::new();
    let mut fields = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => stack.push(Some(HashSet::new())),
            b'[' => stack.push(None),
            b'}' | b']' => {
                stack.pop();
            }
            b'"' => {
                let start = i;
                i += 1;
                let mut escaped = false;
                while i < bytes.len() {
                    if escaped {
                        escaped = false;
                    } else if bytes[i] == b'\\' {
                        escaped = true;
                    } else if bytes[i] == b'"' {
                        break;
                    }
                    i += 1;
                }
                ensure!(i < bytes.len(), "unterminated JSON string");
                let mut next = i + 1;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if next < bytes.len() && bytes[next] == b':' {
                    fields += 1;
                    ensure!(fields <= MAX_PLAN_NODES, "JSON field count exceeded");
                    let key: String = serde_json::from_str(&input[start..=i])?;
                    let Some(Some(keys)) = stack.last_mut() else {
                        bail!("JSON key outside object")
                    };
                    ensure!(keys.insert(key), "duplicate JSON plan field");
                }
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

fn number(value: &Value, key: &str) -> Result<Option<f64>> {
    let Some(v) = value.get(key) else {
        return Ok(None);
    };
    let Some(n) = v.as_f64() else {
        bail!("invalid numeric plan field")
    };
    ensure!(n.is_finite() && n >= 0.0, "invalid numeric plan field");
    Ok(Some(n))
}
fn pg_op(name: &str) -> &'static str {
    match name {
        "Seq Scan" => "Seq Scan",
        "Index Scan" => "Index Scan",
        "Index Only Scan" => "Index Only Scan",
        "Bitmap Heap Scan" => "Bitmap Heap Scan",
        "Bitmap Index Scan" => "Bitmap Index Scan",
        "Sort" => "Sort",
        "Incremental Sort" => "Incremental Sort",
        "Aggregate" => "Aggregate",
        "HashAggregate" => "HashAggregate",
        "Nested Loop" => "Nested Loop",
        "Hash Join" => "Hash Join",
        "Merge Join" => "Merge Join",
        "Gather" => "Gather",
        "Gather Merge" => "Gather Merge",
        "Limit" => "Limit",
        "Materialize" => "Materialize",
        "Hash" => "Hash",
        "Result" => "Result",
        "Append" => "Append",
        "Parallel Seq Scan" => "Parallel Seq Scan",
        _ => "Other operator",
    }
}
fn parse_pg(input: &str) -> Result<Vec<PlanNode>> {
    structural_json_limits(input)?;
    let value: Value = serde_json::from_str(input)?;
    let arr = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("PostgreSQL plan root is not an array"))?;
    ensure!(arr.len() == 1, "PostgreSQL plan must contain one document");
    let root = arr[0]
        .get("Plan")
        .ok_or_else(|| anyhow::anyhow!("missing Plan root"))?;
    let mut count = 0;
    Ok(vec![pg_node(root, 1, &mut count)?])
}
fn pg_node(v: &Value, depth: usize, count: &mut usize) -> Result<PlanNode> {
    ensure!(depth <= MAX_PLAN_DEPTH, "plan operator depth exceeded");
    *count += 1;
    ensure!(*count <= MAX_PLAN_NODES, "plan operator count exceeded");
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid Plan node"))?;
    let name = obj
        .get("Node Type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing Node Type"))?;
    let mut children = Vec::new();
    if let Some(child) = obj.get("Plans") {
        for c in child
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("invalid Plans array"))?
        {
            children.push(pg_node(c, depth + 1, count)?);
        }
    }
    let disk = obj.get("Sort Space Type").and_then(Value::as_str) == Some("Disk");
    let temp = ["Temp Read Blocks", "Temp Written Blocks"]
        .iter()
        .try_fold(false, |hit, key| -> Result<bool> {
            Ok(hit || number(v, key)?.is_some_and(|n| n > 0.0))
        })?;
    Ok(PlanNode {
        operator: pg_op(name),
        estimated_rows: number(v, "Plan Rows")?,
        actual_rows: number(v, "Actual Rows")?,
        actual_executions: number(v, "Actual Loops")?,
        estimated_cost: number(v, "Total Cost")?,
        actual_ms: number(v, "Actual Total Time")?,
        spill: if disk { Some(Spill::DiskSort) } else { None },
        temp_io: temp,
        children,
    })
}

fn xml_op(name: &str) -> &'static str {
    match name {
        "Clustered Index Scan" => "Clustered Index Scan",
        "Clustered Index Seek" => "Clustered Index Seek",
        "Index Scan" => "Index Scan",
        "Index Seek" => "Index Seek",
        "Table Scan" => "Table Scan",
        "Sort" => "Sort",
        "Hash Match" => "Hash Match",
        "Nested Loops" => "Nested Loops",
        "Merge Join" => "Merge Join",
        "Filter" => "Filter",
        "Compute Scalar" => "Compute Scalar",
        "Stream Aggregate" => "Stream Aggregate",
        "Top" => "Top",
        "Parallelism" => "Parallelism",
        "Key Lookup" => "Key Lookup",
        _ => "Other operator",
    }
}
fn attr(e: &BytesStart<'_>, key: &[u8]) -> Result<Option<String>> {
    for a in e.attributes().with_checks(true) {
        let a = a?;
        if a.key.as_ref() == key {
            return Ok(Some(std::str::from_utf8(a.value.as_ref())?.to_owned()));
        }
    }
    Ok(None)
}
fn attr_number(e: &BytesStart<'_>, key: &[u8]) -> Result<Option<f64>> {
    let Some(s) = attr(e, key)? else {
        return Ok(None);
    };
    let n: f64 = s.parse()?;
    ensure!(n.is_finite() && n >= 0.0, "invalid XML numeric plan field");
    Ok(Some(n))
}
fn parse_xml(input: &str) -> Result<Vec<PlanNode>> {
    ensure!(!input.contains('&'), "XML entity references forbidden");
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(false);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut operators: Vec<PlanNode> = Vec::new();
    let mut roots = Vec::new();
    let mut element_count = 0usize;
    let mut seen_root = false;
    let mut seen_query_plan = false;
    let mut seen_statement = false;
    loop {
        let event = reader.read_event()?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let name = e.local_name().as_ref().to_vec();
                ensure!(
                    e.name().as_ref() == name.as_slice(),
                    "prefixed XML element unsupported"
                );
                if let Some(ns) = attr(e, b"xmlns")? {
                    ensure!(
                        ns == "http://schemas.microsoft.com/sqlserver/2004/07/showplan",
                        "unknown Showplan namespace"
                    );
                }
                element_count += 1;
                ensure!(
                    element_count <= MAX_PLAN_NODES,
                    "XML element count exceeded"
                );
                ensure!(stack.len() < MAX_PLAN_DEPTH, "XML depth exceeded");
                if stack.is_empty() {
                    ensure!(
                        !seen_root && e.name().as_ref() == b"ShowPlanXML",
                        "wrong Showplan root"
                    );
                    if let Some(ns) = attr(e, b"xmlns")? {
                        ensure!(
                            ns == "http://schemas.microsoft.com/sqlserver/2004/07/showplan",
                            "unknown Showplan namespace"
                        );
                    }
                    seen_root = true;
                }
                if name == b"Statements" {
                    ensure!(
                        stack.len() == 3
                            && stack[0] == b"ShowPlanXML"
                            && stack[1] == b"BatchSequence"
                            && stack[2] == b"Batch",
                        "unexpected Showplan statement path"
                    );
                }
                if name.starts_with(b"Stmt") && name != b"Statements" {
                    ensure!(
                        stack.len() == 4 && stack[3] == b"Statements",
                        "unexpected Showplan statement node"
                    );
                }
                if name == b"QueryPlan" {
                    ensure!(
                        stack.len() == 5 && stack[4].starts_with(b"Stmt"),
                        "unexpected Showplan QueryPlan path"
                    );
                    seen_query_plan = true;
                }
                if stack.iter().any(|s| s == b"Statements") && name.starts_with(b"Stmt") {
                    seen_statement = true;
                }
                if name == b"RelOp" {
                    ensure!(
                        stack.iter().any(|s| s == b"QueryPlan")
                            && stack.iter().any(|s| s.starts_with(b"Stmt")),
                        "RelOp outside statement QueryPlan"
                    );
                    let op = attr(e, b"PhysicalOp")?
                        .ok_or_else(|| anyhow::anyhow!("missing PhysicalOp"))?;
                    operators.push(PlanNode {
                        operator: xml_op(&op),
                        estimated_rows: attr_number(e, b"EstimateRows")?,
                        actual_rows: None,
                        actual_executions: None,
                        estimated_cost: attr_number(e, b"EstimatedTotalSubtreeCost")?,
                        actual_ms: None,
                        spill: None,
                        temp_io: false,
                        children: Vec::new(),
                    });
                    ensure!(operators.len() <= MAX_PLAN_DEPTH, "RelOp depth exceeded");
                } else if name == b"RunTimeCountersPerThread" {
                    if let Some(node) = operators.last_mut() {
                        for (key, field) in [
                            (b"ActualRows".as_slice(), &mut node.actual_rows),
                            (b"ActualExecutions".as_slice(), &mut node.actual_executions),
                            (b"ActualElapsedms".as_slice(), &mut node.actual_ms),
                        ] {
                            if let Some(n) = attr_number(e, key)? {
                                *field = Some(field.unwrap_or(0.0) + n);
                            }
                        }
                        if let Some(n) = attr_number(e, b"ActualElapsedMs")? {
                            ensure!(
                                attr(e, b"ActualElapsedms")?.is_none(),
                                "ambiguous elapsed counter"
                            );
                            node.actual_ms = Some(node.actual_ms.unwrap_or(0.0) + n);
                        }
                    }
                } else if matches!(
                    name.as_slice(),
                    b"SpillToTempDb" | b"SortSpillDetails" | b"HashSpillDetails"
                ) {
                    if let Some(node) = operators.last_mut() {
                        node.spill = Some(Spill::SqlServerSpill);
                    }
                }
                if matches!(event, Event::Start(_)) {
                    stack.push(name);
                } else if name == b"RelOp" {
                    finish_operator(&mut operators, &mut roots);
                }
            }
            Event::End(ref e) => {
                let name = e.local_name().as_ref().to_vec();
                ensure!(
                    stack.pop().as_deref() == Some(name.as_slice()),
                    "XML element mismatch"
                );
                if name == b"RelOp" {
                    finish_operator(&mut operators, &mut roots);
                }
            }
            Event::DocType(_) | Event::PI(_) | Event::GeneralRef(_) => {
                bail!("XML DTD, PI, or entity forbidden")
            }
            Event::Text(ref text) if !text.as_ref().iter().all(u8::is_ascii_whitespace) => {
                // SQL text and parameter content are never retained, but still permit well-formed text nodes.
            }
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(
        stack.is_empty() && seen_root && seen_query_plan && seen_statement && !roots.is_empty(),
        "incomplete Showplan XML"
    );
    Ok(roots)
}
fn finish_operator(stack: &mut Vec<PlanNode>, roots: &mut Vec<PlanNode>) {
    if let Some(node) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        } else {
            roots.push(node);
        }
    }
}

/// A passive estimate uses only the fixed SELECT family and never ANALYZE.
pub async fn estimated_plan(
    scope: &crate::helper::scope::BoundScope,
    template: &crate::helper::sql::templates::ReviewedSelectTemplate,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<PlanReport> {
    use crate::helper::sql::templates::{TemplateBind, connect_fixture};
    use std::time::Duration;
    let statement = template.reviewed_statement(scope)?;
    let session = connect_fixture(scope, *template, &cancel).await?;
    let result = async {
        session.client.batch_execute("BEGIN READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '1000ms'").await?;
        let row = match statement.bind {
            TemplateBind::None => session.client.query_one(statement.explain_sql, &[]).await?,
            TemplateBind::Integer(n) => {
                session
                    .client
                    .query_one(statement.explain_sql, &[&n])
                    .await?
            }
            TemplateBind::Status(s) => {
                session
                    .client
                    .query_one(statement.explain_sql, &[&s.as_str()])
                    .await?
            }
        };
        let bytes: RawPlanJson = row.try_get(0)?;
        let bytes = bytes.0;
        let mut report = parse_live_estimate(PlanImportFormat::PostgresJson, &bytes)?;
        report.live_metadata_sha256 = Some(session.metadata_sha256.clone());
        Ok(report)
    };
    let outcome = tokio::select! {
        _ = cancel.cancelled() => Err(anyhow::anyhow!("plan collection canceled")),
        result = tokio::time::timeout(Duration::from_secs(15), result) => result.map_err(|_| anyhow::anyhow!("plan collection timed out"))?,
    };
    if outcome.is_err() {
        session.cancel_query().await;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        session.client.batch_execute("ROLLBACK"),
    )
    .await;
    outcome
}
