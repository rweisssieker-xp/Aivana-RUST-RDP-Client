use super::*;
use crate::teaching::{self, Step, Teacher};

#[derive(Default)]
pub(super) struct TeachingState {
    pub teacher:Teacher,
    cursor:usize,
    target:Option<Uuid>,
    approved:bool,
    text:String,
    awaiting_evidence:bool,
    history:Vec<String>,
}
impl TeachingState {
    pub fn observe(&mut self,id:Uuid,action:&InputAction,size:Option<(u16,u16)>){self.teacher.observe(id,action,size);}
    fn reset_replay(&mut self){self.cursor=0;self.target=None;self.approved=false;self.text.clear();self.awaiting_evidence=false;self.history.clear();}
}
impl AivanaApp {
    pub(super) fn poll_teaching(&mut self){
        if let Some(id)=self.teaching.teacher.session {
            if !self.sessions.iter().any(|s|s.id==id&&s.status==SessionStatus::Connected){
                self.teaching.teacher.stop();self.engine.release_inputs(id);
                self.teaching.teacher.notice="Aufnahme gestoppt: Sitzung nicht verbunden".into();
            }
        }
        if let Some(id)=self.teaching.target {
            let valid=self.selected_session==Some(id)&&self.sessions.iter().any(|s|s.id==id&&s.status==SessionStatus::Connected)&&self.latest_frames.get(&id).map(|f|(f.width,f.height))==Some(self.teaching.teacher.procedure.dimensions);
            if !valid {self.engine.release_inputs(id);self.teaching.reset_replay();self.teaching.teacher.notice="Wiedergabe zurückgesetzt: Ziel oder Bildgröße geändert".into();}
        }
    }
    pub(super) fn teaching_view(&mut self,ui:&mut Ui){
        ui.heading("Vormachen → wiederverwendbarer Ablauf");
        ui.label("Bis zu 200 Schritte aus manuellen Eingaben einer Sitzung. Texte, normale Tasten und Tastenkombinationen werden nur als Platzhalter gespeichert. Zwischenablage, Mausbewegungen und Ziehen werden ausgelassen.");
        let session=self.selected_session().cloned();
        let size=session.as_ref().and_then(|s|self.latest_frames.get(&s.id)).map(|f|(f.width,f.height));
        let connected=session.as_ref().is_some_and(|s|s.status==SessionStatus::Connected)&&size.is_some();
        if let Some(s)=&session {ui.label(format!("Ausgewähltes Ziel: {}",s.title));}else{ui.label("Bitte zuerst eine Sitzung auswählen.");}
        let recording=self.teaching.teacher.session.is_some();
        ui.horizontal_wrapped(|ui|{
            if ui.add_enabled(connected&&!recording,egui::Button::new("Neue Demonstration starten")).clicked(){
                self.teaching.reset_replay();self.teaching.teacher.start(session.as_ref().unwrap().id,size.unwrap());
                self.status="Demonstration aktiv: manuelle Eingaben im Remote-Desktop werden erfasst".into();
            }
            if ui.add_enabled(recording,egui::Button::new("Demonstration stoppen")).clicked(){
                if let Some(id)=self.teaching.teacher.session {self.engine.release_inputs(id);}
                self.teaching.teacher.stop();
            }
            if ui.add_enabled(!recording,egui::Button::new("Gespeicherten Ablauf laden")).clicked(){match teaching::load(){Ok(p)=>{self.teaching.reset_replay();self.teaching.teacher.procedure=p;self.status="Verschlüsselten Ablauf geladen; vor jedem Schritt prüfen".into();},Err(e)=>self.status=format!("Ablauf laden: {e:#}")}}
        });
        if recording {ui.colored_label(tw::RED_600,"● Demonstration aktiv – nur die beim Start gewählte Sitzung wird erfasst");}
        ui.label(&self.teaching.teacher.notice);
        let editable=!recording&&!self.teaching.awaiting_evidence;
        let mut changed=false;
        ui.add_enabled_ui(editable,|ui|{
            let p=&mut self.teaching.teacher.procedure;
            changed|=ui.add(egui::TextEdit::singleline(&mut p.title).char_limit(256).hint_text("Titel")).changed();
            ui.label(format!("Aufgezeichnetes Bild: {} × {} · {} Schritte",p.dimensions.0,p.dimensions.1,p.steps.len()));
            ui.label("Erfolgskriterium (im Remote-Bild manuell zu prüfen):");
            changed|=ui.add(egui::TextEdit::multiline(&mut p.success).char_limit(4096).desired_rows(2)).changed();
            ui.label("Wiederherstellung bei Abweichung (keine Zugangsdaten eintragen):");
            changed|=ui.add(egui::TextEdit::multiline(&mut p.recovery).char_limit(4096).desired_rows(2)).changed();
            let mut remove=None;let mut up=None;
            ScrollArea::vertical().id_salt("teaching-review").max_height(240.0).show(ui,|ui|{
                for (i,step) in p.steps.iter_mut().enumerate(){ui.push_id(i,|ui|{ui.horizontal_wrapped(|ui|{
                    ui.label(format!("{}. {}",i+1,step_label(step)));
                    match step {Step::Click{x,y,..}|Step::Scroll{x,y,..}=>{changed|=ui.add(egui::DragValue::new(x).prefix("X ")).changed();changed|=ui.add(egui::DragValue::new(y).prefix("Y ")).changed();},_=>{}}
                    if ui.small_button("Entfernen").clicked(){remove=Some(i);}
                    if i>0&&ui.small_button("↑").clicked(){up=Some(i);}
                });});}
            });
            if let Some(i)=remove{p.steps.remove(i);changed=true;}
            if let Some(i)=up{if i<p.steps.len(){p.steps.swap(i,i-1);changed=true;}}
        });
        if changed{self.teaching.reset_replay();}
        if ui.add_enabled(!recording,egui::Button::new("Geprüften Ablauf verschlüsselt speichern")).clicked(){self.status=match teaching::save(&self.teaching.teacher.procedure){Ok(())=>"Ablauf per Windows DPAPI gespeichert (ersetzt den bisherigen gespeicherten Ablauf)".into(),Err(e)=>format!("Ablauf speichern: {e:#}")};}
        ui.small("Speicher enthält nur diesen Ablauf; ein neuer Speichervorgang ersetzt den bisherigen. Eingabetexte werden nie mitgespeichert.");
        ui.separator();
        if self.teaching.awaiting_evidence {
            ui.label("Schritt gesendet. Wirkung noch nicht verifiziert: Remote-Bild ansehen und gegen das Erfolgskriterium prüfen.");
            if ui.button("Wirkung im Remote-Bild manuell bestätigt → nächster Schritt").clicked(){
                self.teaching.history.push(format!("Schritt {}: Wirkung manuell bestätigt",self.teaching.cursor+1));
                self.teaching.cursor+=1;self.teaching.awaiting_evidence=false;
            }
        } else if let Some(step)=self.teaching.teacher.procedure.steps.get(self.teaching.cursor).cloned(){
            ui.label(format!("Nächster Schritt {}: {}",self.teaching.cursor+1,step_label(&step)));
            if matches!(step,Step::TextRequired){ui.label("Text für diesen einzelnen Schritt neu eingeben; nur im Arbeitsspeicher:");if ui.add(egui::TextEdit::singleline(&mut self.teaching.text).password(true).char_limit(4096)).changed(){self.teaching.approved=false;}}
            ui.checkbox(&mut self.teaching.approved,"Ziel, sichtbares Element und Wirkung geprüft; diesen einen Schritt freigeben");
            let enabled=!recording&&connected&&self.teaching.approved&&(!matches!(step,Step::TextRequired)||!self.teaching.text.is_empty());
            if ui.add_enabled(enabled,egui::Button::new("Genau diesen Schritt ausführen")).clicked(){
                let id=session.as_ref().unwrap().id;
                let result=(||->anyhow::Result<()>{
                    self.teaching.teacher.procedure.validate()?;
                    let actions=self.teaching.teacher.procedure.actions(&step,size.unwrap(),&self.teaching.text)?;
                    let policy=crate::policy::PolicyEngine;
                    if actions.iter().any(|a|policy.decision_for(a)==PolicyDecision::Deny){anyhow::bail!("Schritt durch Sicherheitsrichtlinie gesperrt");}
                    for action in actions {self.engine.send_input(id,action)?;}
                    Ok(())
                })();
                self.engine.release_inputs(id);self.teaching.approved=false;self.teaching.text.clear();
                match result{Ok(())=>{self.teaching.target=Some(id);self.teaching.awaiting_evidence=true;self.status="Ein Schritt gesendet; Wirkung manuell prüfen".into();},Err(e)=>{self.teaching.history.push(format!("Schritt {}: Versand abgebrochen; Wirkung unklar",self.teaching.cursor+1));self.status=format!("Schritt gestoppt: {e:#}");}}
            }
        }else if !self.teaching.teacher.procedure.steps.is_empty(){ui.label("Alle Schritte einzeln ausgeführt und manuell bestätigt.");}
        if ui.button("Wiedergabe abbrechen / zurücksetzen").clicked(){if let Some(id)=self.teaching.target {self.engine.release_inputs(id);}self.teaching.reset_replay();}
        for entry in self.teaching.history.iter().rev().take(10){ui.small(entry);}
    }
}
fn step_label(step:&Step)->String{match step {
    Step::Click{button,double,..}=>format!("{} {button:?}",if *double{"Doppelklick"}else{"Klick"}),
    Step::Scroll{delta,..}=>format!("Scrollen {delta}"),
    Step::Navigation{code}=>format!("Navigationstaste {code:#x} (Drücken + Loslassen)"),
    Step::TextRequired=>"Eingabe-Platzhalter – Inhalt wurde nicht aufgezeichnet".into(),
}}
