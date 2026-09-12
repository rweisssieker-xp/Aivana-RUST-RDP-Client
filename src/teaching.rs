//! A bounded demonstration recorder. Text and keylog material never enter the procedure.
use crate::models::{InputAction, MouseButton};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[path = "icon_anchor.rs"]
pub mod icons;

pub const MAX_STEPS: usize = 200;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum Step {
    IconClick {
        anchor: icons::IconAnchor,
        button: MouseButton,
        double: bool,
    },
    TransferClick {
        target: crate::transferable::LogicalTarget,
        button: MouseButton,
        double: bool,
    },
    Parameter {
        name: String,
    },
    SemanticClick {
        anchor: crate::vision::Anchor,
        button: MouseButton,
        double: bool,
    },
    Click {
        x: u16,
        y: u16,
        button: MouseButton,
        double: bool,
    },
    Scroll {
        x: u16,
        y: u16,
        delta: i16,
    },
    Navigation {
        code: u16,
    },
    TextRequired,
}
fn navigation(code: u16) -> bool {
    matches!(
        code,
        0x01 | 0x0f | 0x1c | 0x147 | 0x148 | 0x149 | 0x14b | 0x14d | 0x14f | 0x150 | 0x151
    )
}
fn modifier(code: u16) -> u16 {
    match code {
        0x2a => 1,
        0x36 => 2,
        0x1d => 4,
        0x11d => 8,
        0x38 => 16,
        0x138 => 32,
        0x15b => 64,
        0x15c => 128,
        _ => 0,
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Procedure {
    pub title: String,
    pub dimensions: (u16, u16),
    pub steps: Vec<Step>,
    pub success: String,
    pub recovery: String,
    #[serde(default)]
    pub expected_after: std::collections::BTreeMap<usize, crate::vision::Anchor>,
    #[serde(default)]
    pub expected_final: Option<crate::vision::Anchor>,
}
impl Default for Procedure {
    fn default() -> Self {
        Self {
            title: "Neuer Ablauf".into(),
            dimensions: (0, 0),
            steps: vec![],
            success: String::new(),
            recovery: String::new(),
            expected_after: Default::default(),
            expected_final: None,
        }
    }
}
impl Procedure {
    pub fn validate(&self) -> Result<()> {
        if self.dimensions.0 == 0
            || self.dimensions.1 == 0
            || self.steps.is_empty()
            || self.steps.len() > MAX_STEPS
        {
            bail!("Ablauf oder Bildgröße ungültig");
        }
        if self.success.trim().is_empty() || self.recovery.trim().is_empty() {
            bail!("Erfolgskriterium und Wiederherstellung ergänzen");
        }
        if self.title.len() > 256 || self.success.len() > 4096 || self.recovery.len() > 4096 {
            bail!("Notizen zu lang");
        }
        if self.expected_after.keys().any(|i| *i >= self.steps.len()) {
            bail!("Nachbedingung verweist auf unbekannten Schritt");
        }
        for anchor in self
            .expected_after
            .values()
            .chain(self.expected_final.iter())
        {
            if !crate::vision::safe_anchor_text(&anchor.label) || anchor.context.len() > 256 {
                bail!(
                    "Sichtbare Nachbedingung benötigt ein nicht vertrauliches Zielwort und gültigen Kontext"
                );
            }
        }
        for step in &self.steps {
            if let Step::IconClick { anchor, .. } = step {
                anchor.validate()?;
            } else if let Step::TransferClick { target, .. } = step {
                if !crate::vision::safe_anchor_text(&target.anchor.label)
                    || target.anchor.context.len() > 256
                    || target
                        .context_offset
                        .is_some_and(|(x, y)| !x.is_finite() || !y.is_finite())
                {
                    bail!("Ungültiger übertragbarer Anker");
                }
            } else if let Step::Parameter { name } = step {
                crate::transferable::validate_parameter(name)?;
            } else if let Step::SemanticClick { anchor, .. } = step {
                if anchor.label.trim().is_empty()
                    || anchor.label.len() > 256
                    || anchor.context.len() > 256
                {
                    bail!("Ungültiger semantischer Anker");
                }
            } else {
                self.actions(step, self.dimensions, "")?;
            }
        }
        Ok(())
    }
    pub fn actions_on_frame(
        &self,
        step: &Step,
        frame: &crate::models::FrameUpdate,
        screen: Option<&crate::vision::Screen>,
        text: &str,
    ) -> Result<Vec<InputAction>> {
        if let Step::IconClick {
            anchor,
            button,
            double,
        } = step
        {
            let found = anchor.resolve(frame)?;
            let (x, y) = found.bounds.center();
            return Ok(vec![if *double {
                InputAction::DoubleClick {
                    x,
                    y,
                    button: *button,
                }
            } else {
                InputAction::Click {
                    x,
                    y,
                    button: *button,
                }
            }]);
        }
        if let Step::TransferClick {
            target,
            button,
            double,
        } = step
        {
            let screen = screen.ok_or_else(|| anyhow::anyhow!("Aktuelles Zielbild lokal lesen"))?;
            if !screen.matches(frame) {
                bail!("OCR veraltet: Zielbild erneut lesen");
            }
            let (x, y) = target.resolve(screen)?.center();
            return Ok(vec![if *double {
                InputAction::DoubleClick {
                    x,
                    y,
                    button: *button,
                }
            } else {
                InputAction::Click {
                    x,
                    y,
                    button: *button,
                }
            }]);
        }
        if let Step::SemanticClick {
            anchor,
            button,
            double,
        } = step
        {
            let screen =
                screen.ok_or_else(|| anyhow::anyhow!("Zuerst aktuelles Bild lokal lesen"))?;
            if !screen.matches(frame) {
                bail!("OCR veraltet: aktuelles Bild erneut lesen und freigeben");
            }
            let (x, y) = screen.resolve(anchor)?.center();
            return Ok(vec![if *double {
                InputAction::DoubleClick {
                    x,
                    y,
                    button: *button,
                }
            } else {
                InputAction::Click {
                    x,
                    y,
                    button: *button,
                }
            }]);
        }
        // Keyboard and parameter steps are independent of desktop dimensions.
        let size = if matches!(
            step,
            Step::Navigation { .. } | Step::TextRequired | Step::Parameter { .. }
        ) {
            self.dimensions
        } else {
            (frame.width, frame.height)
        };
        self.actions(step, size, text)
    }
    pub fn actions(&self, step: &Step, size: (u16, u16), text: &str) -> Result<Vec<InputAction>> {
        if size != self.dimensions {
            bail!("Bildgröße geändert: Ablauf erneut prüfen / vormachen");
        }
        let point = |x: u16, y: u16| -> Result<()> {
            if x >= size.0 || y >= size.1 {
                bail!("Koordinate außerhalb des Bildes");
            }
            Ok(())
        };
        Ok(match *step {
            Step::IconClick { .. } | Step::SemanticClick { .. } | Step::TransferClick { .. } => {
                bail!("Semantischer Schritt benötigt frische OCR desselben Bildes")
            }
            Step::Click {
                x,
                y,
                button,
                double,
            } => {
                point(x, y)?;
                vec![if double {
                    InputAction::DoubleClick { x, y, button }
                } else {
                    InputAction::Click { x, y, button }
                }]
            }
            Step::Scroll { x, y, delta } => {
                point(x, y)?;
                vec![InputAction::Scroll { x, y, delta }]
            }
            Step::Navigation { code } => {
                if !navigation(code) {
                    bail!("Taste nicht freigegeben");
                }
                vec![
                    InputAction::Key {
                        scan_code: code,
                        pressed: true,
                    },
                    InputAction::Key {
                        scan_code: code,
                        pressed: false,
                    },
                ]
            }
            Step::Parameter { ref name } => {
                crate::transferable::validate_parameter(name)?;
                if text.is_empty() || text.len() > 4096 {
                    bail!("Parameterwert fehlt oder zu lang");
                }
                vec![InputAction::TypeText {
                    text: text.to_owned(),
                }]
            }
            Step::TextRequired => {
                if text.len() > 4096 {
                    bail!("Texteingabe zu lang");
                }
                vec![InputAction::TypeText {
                    text: text.to_owned(),
                }]
            }
        })
    }
}

/// Inert validation; runtime parameter values are never persisted in a procedure.
pub fn validate_workflow_procedure(procedure: &Procedure) -> Result<()> {
    anyhow::ensure!(
        serde_json::to_vec(procedure)?.len() <= 192 * 1024,
        "Workflow procedure exceeds 192 KiB"
    );
    let values = procedure
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::Parameter { name } => Some((name.clone(), "validation-placeholder".to_owned())),
            _ => None,
        })
        .collect();
    crate::transferable::validate_run(procedure, &values)
}

/// Evidence means this expected text is visible in the current destination frame.
/// It does not establish causation or a backend transaction result.
pub fn verify_visible_assertion(
    frame: &crate::models::FrameUpdate,
    screen: Option<&crate::vision::Screen>,
    expected: &crate::vision::Anchor,
    after: (Uuid, u64, chrono::DateTime<chrono::Utc>),
) -> Result<crate::vision::Bounds> {
    if frame.session_id != after.0 || frame.captured_at <= after.2 {
        bail!("Ein neueres Bild derselben Zielsitzung ist erforderlich");
    }
    let screen =
        screen.ok_or_else(|| anyhow::anyhow!("Aktuelle OCR für Ergebnisnachweis fehlt"))?;
    if !screen.matches(frame) {
        bail!("Ergebnis-OCR gehört nicht zum aktuellen Zielbild");
    }
    screen.resolve(expected)
}
#[derive(Default)]
pub struct Teacher {
    pub session: Option<Uuid>,
    pub procedure: Procedure,
    pub notice: String,
    pending_key: Option<u16>,
    pending_button: Option<(u16, u16, MouseButton)>,
    held_modifiers: u16,
    last_paired_click: Option<(Instant, usize)>,
}
impl Teacher {
    pub fn is_recording(&self) -> bool {
        self.session.is_some()
    }
    pub fn start(&mut self, id: Uuid, size: (u16, u16)) {
        *self = Self {
            session: Some(id),
            procedure: Procedure {
                dimensions: size,
                ..Default::default()
            },
            ..Default::default()
        };
    }
    pub fn stop(&mut self) {
        self.session = None;
        self.pending_key = None;
        self.pending_button = None;
        self.held_modifiers = 0;
        self.last_paired_click = None;
    }
    #[cfg(test)]
    pub fn observe(&mut self, id: Uuid, action: &InputAction, size: Option<(u16, u16)>) {
        self.observe_at(id, action, size, Instant::now());
    }
    pub fn observe_at(
        &mut self,
        id: Uuid,
        action: &InputAction,
        size: Option<(u16, u16)>,
        now: Instant,
    ) {
        if self.session != Some(id) {
            return;
        }
        if size != Some(self.procedure.dimensions) {
            self.stop();
            self.notice = "Aufnahme gestoppt: Bildgröße geändert".into();
            return;
        }
        if !matches!(action, InputAction::PointerButton { .. }) {
            self.last_paired_click = None;
        }
        let step = match action {
            InputAction::PointerButton { .. }
            | InputAction::Click { .. }
            | InputAction::DoubleClick { .. }
            | InputAction::Scroll { .. }
                if self.held_modifiers != 0 =>
            {
                self.pending_button = None;
                self.last_paired_click = None;
                Some(Step::TextRequired)
            }
            InputAction::TypeText { .. } | InputAction::Hotkey { .. } => Some(Step::TextRequired),
            InputAction::Key { scan_code, pressed } => {
                let mask = modifier(*scan_code);
                if mask != 0 {
                    self.pending_key = None;
                    self.pending_button = None;
                    self.last_paired_click = None;
                    if *pressed {
                        self.held_modifiers |= mask;
                        Some(Step::TextRequired)
                    } else {
                        self.held_modifiers &= !mask;
                        None
                    }
                } else if self.held_modifiers != 0 {
                    self.pending_key = None;
                    if *pressed {
                        Some(Step::TextRequired)
                    } else {
                        None
                    }
                } else if navigation(*scan_code) {
                    if *pressed {
                        self.pending_key = Some(*scan_code);
                        None
                    } else if self.pending_key.take() == Some(*scan_code) {
                        Some(Step::Navigation { code: *scan_code })
                    } else {
                        None
                    }
                } else {
                    self.pending_key = None;
                    if *pressed {
                        Some(Step::TextRequired)
                    } else {
                        None
                    }
                }
            }
            InputAction::PointerButton {
                x,
                y,
                button,
                pressed,
            } => {
                if *pressed {
                    if self.procedure.steps.last()
                        != Some(&Step::Click {
                            x: *x,
                            y: *y,
                            button: *button,
                            double: false,
                        })
                    {
                        self.last_paired_click = None;
                    }
                    self.pending_button = Some((*x, *y, *button));
                    None
                } else if self.pending_button.take() == Some((*x, *y, *button)) {
                    if let Some((at, index)) = self.last_paired_click.take() {
                        if now.saturating_duration_since(at) <= Duration::from_millis(350)
                            && index + 1 == self.procedure.steps.len()
                            && self.procedure.steps.get(index)
                                == Some(&Step::Click {
                                    x: *x,
                                    y: *y,
                                    button: *button,
                                    double: false,
                                })
                        {
                            self.procedure.steps[index] = Step::Click {
                                x: *x,
                                y: *y,
                                button: *button,
                                double: true,
                            };
                            return;
                        }
                    }
                    self.last_paired_click = Some((now, self.procedure.steps.len()));
                    Some(Step::Click {
                        x: *x,
                        y: *y,
                        button: *button,
                        double: false,
                    })
                } else {
                    self.last_paired_click = None;
                    self.notice = "Ziehen ausgelassen; manuell erneut prüfen".into();
                    None
                }
            }
            InputAction::Click { x, y, button } => Some(Step::Click {
                x: *x,
                y: *y,
                button: *button,
                double: false,
            }),
            InputAction::DoubleClick { x, y, button } => Some(Step::Click {
                x: *x,
                y: *y,
                button: *button,
                double: true,
            }),
            InputAction::Scroll { x, y, delta } => Some(Step::Scroll {
                x: *x,
                y: *y,
                delta: *delta,
            }),
            _ => None,
        };
        if let Some(step) = step {
            if step == Step::TextRequired && self.procedure.steps.last() == Some(&step) {
                return;
            }
            if self.procedure.steps.len() < MAX_STEPS {
                self.procedure.steps.push(step);
            }
            if self.procedure.steps.len() >= MAX_STEPS {
                self.stop();
                self.notice = "Limit von 200 Schritten erreicht; Aufnahme gestoppt".into();
            }
        }
    }
}
pub fn save(procedure: &Procedure) -> Result<()> {
    if !cfg!(windows) {
        bail!("Verschlüsselte Abläufe benötigen Windows DPAPI");
    }
    procedure.validate()?;
    let path = crate::security::app_data_file("teaching.dpapi")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = crate::security::protect_secret(&serde_json::to_vec(procedure)?)?;
    anyhow::ensure!(
        bytes.len() <= 128 * 1024,
        "Einzelablauf überschreitet 128 KiB; benannte Bibliothek verwenden"
    );
    crate::security::atomic_write(&path, &bytes)?;
    Ok(())
}
pub fn load() -> Result<Procedure> {
    if !cfg!(windows) {
        bail!("Verschlüsselte Abläufe benötigen Windows DPAPI");
    }
    let path = crate::security::app_data_file("teaching.dpapi")?;
    if std::fs::metadata(&path)?.len() > 128 * 1024 {
        bail!("Ablaufdatei zu groß");
    }
    let procedure: Procedure =
        serde_json::from_slice(&crate::security::unprotect_secret(&std::fs::read(path)?)?)?;
    procedure.validate()?;
    Ok(procedure)
}

/// Named DPAPI library, retaining the legacy single-procedure file for compatibility.
pub fn save_named(procedure: &Procedure) -> Result<()> {
    if !cfg!(windows) {
        bail!("Verschlüsselte Ablaufbibliothek benötigt Windows DPAPI");
    }
    procedure.validate()?;
    if procedure.title.trim().is_empty() {
        bail!("Ablauf benötigt einen Namen");
    }
    let mut library = load_library()?;
    if let Some(existing) = library.iter_mut().find(|p| p.title == procedure.title) {
        *existing = procedure.clone();
    } else {
        if library.len() >= 32 {
            bail!("Bibliothek voll: maximal 32 benannte Abläufe");
        }
        library.push(procedure.clone());
    }
    let path = crate::security::app_data_file("procedures.dpapi")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let encrypted = crate::security::protect_secret(&serde_json::to_vec(&library)?)?;
    anyhow::ensure!(
        encrypted.len() <= 4 * 1024 * 1024,
        "Verschlüsselte Ablaufbibliothek überschreitet 4 MiB"
    );
    crate::security::atomic_write(&path, &encrypted)?;
    Ok(())
}
pub fn load_library() -> Result<Vec<Procedure>> {
    if !cfg!(windows) {
        bail!("Verschlüsselte Ablaufbibliothek benötigt Windows DPAPI");
    }
    let path = crate::security::app_data_file("procedures.dpapi")?;
    if !path.exists() {
        return Ok(vec![]);
    }
    if std::fs::metadata(&path)?.len() > 4 * 1024 * 1024 {
        bail!("Ablaufbibliothek zu groß");
    }
    let library: Vec<Procedure> =
        serde_json::from_slice(&crate::security::unprotect_secret(&std::fs::read(path)?)?)?;
    if library.len() > 32 {
        bail!("Zu viele Abläufe");
    }
    for procedure in &library {
        procedure.validate()?;
    }
    Ok(library)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn newer_frame_is_not_success_without_expected_visible_state() {
        let mut frame = crate::models::FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 800,
            height: 600,
            pixels_rgba: vec![],
            dirty_regions: vec![],
            frame_hash: 9,
            captured_at: chrono::Utc::now(),
        };
        let after = (
            frame.session_id,
            8,
            frame.captured_at - chrono::Duration::seconds(1),
        );
        let expected = crate::vision::Anchor {
            label: "Completed".into(),
            context: String::new(),
        };
        let mut screen = crate::vision::Screen {
            session: frame.session_id,
            width: 800,
            height: 600,
            frame_hash: 9,
            captured_at: frame.captured_at,
            words: vec![],
        };
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_err());
        assert_eq!(
            verify_visible_assertion(&frame, Some(&screen), &expected, after)
                .unwrap_err()
                .downcast_ref::<crate::vision::AnchorResolutionError>(),
            Some(&crate::vision::AnchorResolutionError::Missing)
        );
        screen.words.push(crate::vision::Word {
            text: "Completed".into(),
            bounds: crate::vision::Bounds {
                x: 50,
                y: 50,
                w: 80,
                h: 20,
            },
        });
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_ok());
        screen.words.push(screen.words[0].clone());
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_err());
        assert_eq!(
            verify_visible_assertion(&frame, Some(&screen), &expected, after)
                .unwrap_err()
                .downcast_ref::<crate::vision::AnchorResolutionError>(),
            Some(&crate::vision::AnchorResolutionError::Ambiguous)
        );
        screen.words.pop();
        frame.frame_hash += 1;
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_err());
        frame.frame_hash = 9;
        frame.captured_at = after.2;
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_err());
        frame.captured_at = screen.captured_at;
        frame.session_id = Uuid::new_v4();
        assert!(verify_visible_assertion(&frame, Some(&screen), &expected, after).is_err());
    }
    #[test]
    fn old_procedures_load_without_new_assertion_fields() {
        let p:Procedure=serde_json::from_str(r#"{"title":"Legacy","dimensions":[800,600],"steps":["TextRequired"],"success":"Check","recovery":"Undo"}"#).unwrap();
        p.validate().unwrap();
        assert!(p.expected_after.is_empty());
        assert!(p.expected_final.is_none());
        let mut bad = p;
        bad.expected_after.insert(
            9,
            crate::vision::Anchor {
                label: "Completed".into(),
                context: String::new(),
            },
        );
        assert!(bad.validate().is_err());
    }
    #[test]
    fn portable_actions_bind_current_destination_and_reject_stale_ocr() {
        let frame = crate::models::FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 1200,
            height: 900,
            frame_hash: 42,
            captured_at: chrono::Utc::now(),
            pixels_rgba: vec![],
            dirty_regions: vec![],
        };
        let screen = crate::vision::Screen {
            session: frame.session_id,
            width: 1200,
            height: 900,
            frame_hash: 42,
            captured_at: frame.captured_at,
            words: vec![crate::vision::Word {
                text: "Save".into(),
                bounds: crate::vision::Bounds {
                    x: 700,
                    y: 600,
                    w: 80,
                    h: 20,
                },
            }],
        };
        let step = Step::TransferClick {
            target: crate::transferable::LogicalTarget {
                anchor: crate::vision::Anchor {
                    label: "Save".into(),
                    context: String::new(),
                },
                context_offset: None,
            },
            button: MouseButton::Left,
            double: false,
        };
        let p = Procedure {
            dimensions: (800, 600),
            ..Default::default()
        };
        assert!(matches!(
            p.actions_on_frame(&step, &frame, Some(&screen), "")
                .unwrap()[0],
            InputAction::Click { x: 740, y: 610, .. }
        ));
        let mut stale = screen.clone();
        stale.session = Uuid::new_v4();
        assert!(p.actions_on_frame(&step, &frame, Some(&stale), "").is_err());
        stale = screen.clone();
        stale.frame_hash += 1;
        assert!(p.actions_on_frame(&step, &frame, Some(&stale), "").is_err());
        stale = screen;
        stale.captured_at -= chrono::Duration::milliseconds(1);
        assert!(p.actions_on_frame(&step, &frame, Some(&stale), "").is_err());
    }
    #[test]
    fn parameters_store_names_only_and_require_fresh_values() {
        let p = Procedure {
            dimensions: (800, 600),
            ..Default::default()
        };
        let step = Step::Parameter {
            name: "service_name".into(),
        };
        assert!(p.actions(&step, (800, 600), "").is_err());
        let actions = p
            .actions(&step, (800, 600), "destination-only-value")
            .unwrap();
        assert!(
            matches!(&actions[0],InputAction::TypeText{text} if text=="destination-only-value")
        );
        let json = serde_json::to_string(&step).unwrap();
        assert!(!json.contains("destination-only-value"));
        assert!(json.contains("service_name"));
        assert_eq!(
            serde_json::from_str::<Step>("\"TextRequired\"").unwrap(),
            Step::TextRequired
        );
    }
    #[test]
    fn modified_clicks_and_scroll_stay_opaque() {
        for modifier in [0x1d, 0x2a] {
            let id = Uuid::new_v4();
            let mut t = Teacher::default();
            t.start(id, (800, 600));
            // Even a button pressed before the modifier cannot survive as a plain click.
            t.observe(
                id,
                &InputAction::PointerButton {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                    pressed: true,
                },
                Some((800, 600)),
            );
            t.observe(
                id,
                &InputAction::Key {
                    scan_code: modifier,
                    pressed: true,
                },
                Some((800, 600)),
            );
            for action in [
                InputAction::PointerButton {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                    pressed: false,
                },
                InputAction::PointerButton {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                    pressed: true,
                },
                InputAction::Click {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                },
                InputAction::DoubleClick {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                },
                InputAction::Scroll {
                    x: 5,
                    y: 5,
                    delta: 120,
                },
            ] {
                t.observe(id, &action, Some((800, 600)));
            }
            t.observe(
                id,
                &InputAction::Key {
                    scan_code: modifier,
                    pressed: false,
                },
                Some((800, 600)),
            );
            t.observe(
                id,
                &InputAction::PointerButton {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                    pressed: false,
                },
                Some((800, 600)),
            );
            assert_eq!(t.procedure.steps, vec![Step::TextRequired]);
            assert!(t.pending_button.is_none());
            assert!(t.last_paired_click.is_none());
            t.observe(
                id,
                &InputAction::Click {
                    x: 5,
                    y: 5,
                    button: MouseButton::Left,
                },
                Some((800, 600)),
            );
            assert!(matches!(
                t.procedure.steps.last(),
                Some(Step::Click { double: false, .. })
            ));
        }
    }
    #[test]
    fn shifted_tab_stays_opaque_until_modifiers_released() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        for (code, pressed) in [(0x2a, true), (0x0f, true), (0x0f, false), (0x2a, false)] {
            t.observe(
                id,
                &InputAction::Key {
                    scan_code: code,
                    pressed,
                },
                Some((800, 600)),
            );
        }
        assert_eq!(t.procedure.steps, vec![Step::TextRequired]);
        assert_eq!(t.held_modifiers, 0);
        for pressed in [true, false] {
            t.observe(
                id,
                &InputAction::Key {
                    scan_code: 0x0f,
                    pressed,
                },
                Some((800, 600)),
            );
        }
        assert_eq!(
            t.procedure.steps.last(),
            Some(&Step::Navigation { code: 0x0f })
        );
        t.observe(
            id,
            &InputAction::Key {
                scan_code: 0x11d,
                pressed: true,
            },
            Some((800, 600)),
        );
        t.stop();
        assert_eq!(t.held_modifiers, 0);
    }
    #[test]
    fn paired_double_click_coalesces_only_matching_recent_pairs() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        let now = Instant::now();
        for (millis, x) in [(0, 5), (100, 5), (200, 5), (700, 5), (800, 6)] {
            for pressed in [true, false] {
                t.observe_at(
                    id,
                    &InputAction::PointerButton {
                        x,
                        y: 5,
                        button: MouseButton::Left,
                        pressed,
                    },
                    Some((800, 600)),
                    now + Duration::from_millis(millis),
                );
            }
        }
        assert_eq!(t.procedure.steps.len(), 4);
        assert_eq!(
            t.procedure.steps[0],
            Step::Click {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                double: true
            }
        );
        assert!(matches!(
            t.procedure.steps[1],
            Step::Click { double: false, .. }
        ));
        assert!(matches!(
            t.procedure.steps[2],
            Step::Click { double: false, .. }
        ));
        assert!(matches!(
            t.procedure.steps[3],
            Step::Click {
                x: 6,
                double: false,
                ..
            }
        ));
    }
    #[test]
    fn pointer_pairs_are_atomic_and_drags_are_omitted() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        t.observe(
            id,
            &InputAction::PointerButton {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                pressed: true,
            },
            Some((800, 600)),
        );
        t.observe(
            id,
            &InputAction::PointerButton {
                x: 6,
                y: 5,
                button: MouseButton::Left,
                pressed: false,
            },
            Some((800, 600)),
        );
        assert!(t.procedure.steps.is_empty());
        t.observe(
            id,
            &InputAction::PointerButton {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                pressed: true,
            },
            Some((800, 600)),
        );
        t.stop();
        assert!(t.pending_button.is_none());
        assert!(t.procedure.steps.is_empty());
    }
    #[test]
    fn secrets_and_clipboard_never_persist() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        for a in [
            InputAction::TypeText {
                text: "secret-password".into(),
            },
            InputAction::ClipboardFiles {
                paths: vec!["sensitive".into()],
            },
            InputAction::ClipboardDownload {
                directory: "private".into(),
            },
            InputAction::Key {
                scan_code: 0x1e,
                pressed: true,
            },
            InputAction::MovePointer { x: 1, y: 2 },
        ] {
            t.observe(id, &a, Some((800, 600)));
        }
        assert_eq!(t.procedure.steps, vec![Step::TextRequired]);
        assert!(
            !serde_json::to_string(&t.procedure)
                .unwrap()
                .contains("secret-password")
        );
    }
    #[test]
    fn isolated_and_bounded() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        let a = InputAction::Click {
            x: 1,
            y: 1,
            button: MouseButton::Left,
        };
        t.observe(Uuid::new_v4(), &a, Some((800, 600)));
        assert!(t.procedure.steps.is_empty());
        for _ in 0..400 {
            t.observe(id, &a, Some((800, 600)));
        }
        assert_eq!(t.procedure.steps.len(), MAX_STEPS);
        assert!(t.session.is_none());
    }
    #[test]
    fn dimensions_stop_recording_and_block_replay() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        t.observe(id, &InputAction::Screenshot, Some((801, 600)));
        assert!(t.session.is_none());
        assert!(
            t.procedure
                .actions(&Step::TextRequired, (801, 600), "")
                .is_err()
        );
    }
    #[test]
    fn only_balanced_navigation_survives() {
        let id = Uuid::new_v4();
        let mut t = Teacher::default();
        t.start(id, (800, 600));
        t.observe(
            id,
            &InputAction::Key {
                scan_code: 0x0f,
                pressed: true,
            },
            Some((800, 600)),
        );
        assert!(t.procedure.steps.is_empty());
        t.observe(
            id,
            &InputAction::Key {
                scan_code: 0x0f,
                pressed: false,
            },
            Some((800, 600)),
        );
        let actions = t
            .procedure
            .actions(&t.procedure.steps[0], (800, 600), "")
            .unwrap();
        assert!(matches!(
            actions.last(),
            Some(InputAction::Key { pressed: false, .. })
        ));
        t.stop();
        assert!(t.pending_key.is_none());
        assert!(
            t.procedure
                .actions(&Step::Navigation { code: 0x1e }, (800, 600), "")
                .is_err()
        );
    }
}

#[cfg(test)]
mod semantic_tests {
    use super::*;
    #[test]
    fn semantic_replay_uses_current_ocr_and_blocks_stale_image() {
        let f = crate::models::FrameUpdate {
            session_id: Uuid::new_v4(),
            width: 800,
            height: 600,
            pixels_rgba: vec![],
            dirty_regions: vec![],
            frame_hash: 8,
            captured_at: chrono::Utc::now(),
        };
        let screen = crate::vision::Screen {
            session: f.session_id,
            width: 800,
            height: 600,
            frame_hash: 8,
            captured_at: f.captured_at,
            words: vec![crate::vision::Word {
                text: "Save".into(),
                bounds: crate::vision::Bounds {
                    x: 500,
                    y: 300,
                    w: 100,
                    h: 30,
                },
            }],
        };
        let step = Step::SemanticClick {
            anchor: crate::vision::Anchor {
                label: "Save".into(),
                context: String::new(),
            },
            button: MouseButton::Left,
            double: false,
        };
        let p = Procedure::default();
        assert!(p.actions(&step, (800, 600), "").is_err());
        let actions = p.actions_on_frame(&step, &f, Some(&screen), "").unwrap();
        assert!(matches!(
            actions[0],
            InputAction::Click { x: 550, y: 315, .. }
        ));
        let mut stale = screen;
        stale.frame_hash = 7;
        assert!(p.actions_on_frame(&step, &f, Some(&stale), "").is_err());
    }
}
