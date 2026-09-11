//! A bounded demonstration recorder. Text and keylog material never enter the procedure.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::{InputAction, MouseButton};

pub const MAX_STEPS: usize = 200;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Step {
    Click { x:u16, y:u16, button:MouseButton, double:bool },
    Scroll { x:u16, y:u16, delta:i16 },
    Navigation { code:u16 },
    TextRequired,
}
fn navigation(code:u16)->bool { matches!(code,0x01|0x0f|0x1c|0x147|0x148|0x149|0x14b|0x14d|0x14f|0x150|0x151) }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Procedure {
    pub title:String,
    pub dimensions:(u16,u16),
    pub steps:Vec<Step>,
    pub success:String,
    pub recovery:String,
}
impl Default for Procedure {
    fn default()->Self { Self { title:"Neuer Ablauf".into(), dimensions:(0,0), steps:vec![], success:String::new(), recovery:String::new() } }
}
impl Procedure {
    pub fn validate(&self)->Result<()> {
        if self.dimensions.0==0 || self.dimensions.1==0 || self.steps.is_empty() || self.steps.len()>MAX_STEPS { bail!("Ablauf oder Bildgröße ungültig"); }
        if self.success.trim().is_empty() || self.recovery.trim().is_empty() { bail!("Erfolgskriterium und Wiederherstellung ergänzen"); }
        if self.title.len()>256 || self.success.len()>4096 || self.recovery.len()>4096 { bail!("Notizen zu lang"); }
        for step in &self.steps { self.actions(step,self.dimensions,"")?; }
        Ok(())
    }
    pub fn actions(&self,step:&Step,size:(u16,u16),text:&str)->Result<Vec<InputAction>> {
        if size!=self.dimensions { bail!("Bildgröße geändert: Ablauf erneut prüfen / vormachen"); }
        let point=|x:u16,y:u16|->Result<()>{if x>=size.0||y>=size.1 {bail!("Koordinate außerhalb des Bildes");} Ok(())};
        Ok(match *step {
            Step::Click{x,y,button,double}=>{point(x,y)?;vec![if double{InputAction::DoubleClick{x,y,button}}else{InputAction::Click{x,y,button}}]},
            Step::Scroll{x,y,delta}=>{point(x,y)?;vec![InputAction::Scroll{x,y,delta}]},
            Step::Navigation{code}=>{if !navigation(code){bail!("Taste nicht freigegeben");}vec![InputAction::Key{scan_code:code,pressed:true},InputAction::Key{scan_code:code,pressed:false}]},
            Step::TextRequired=>{if text.len()>4096{bail!("Texteingabe zu lang");}vec![InputAction::TypeText{text:text.to_owned()}]},
        })
    }
}
#[derive(Default)]
pub struct Teacher {
    pub session:Option<Uuid>,
    pub procedure:Procedure,
    pub notice:String,
    pending_key:Option<u16>,
    pending_button:Option<(u16,u16,MouseButton)>,
}
impl Teacher {
    pub fn start(&mut self,id:Uuid,size:(u16,u16)) { *self=Self {session:Some(id),procedure:Procedure{dimensions:size,..Default::default()},..Default::default()}; }
    pub fn stop(&mut self){self.session=None;self.pending_key=None;self.pending_button=None;}
    pub fn observe(&mut self,id:Uuid,action:&InputAction,size:Option<(u16,u16)>){
        if self.session!=Some(id){return;}
        if size!=Some(self.procedure.dimensions){self.stop();self.notice="Aufnahme gestoppt: Bildgröße geändert".into();return;}
        let step=match action {
            InputAction::TypeText{..}|InputAction::Hotkey{..}=>Some(Step::TextRequired),
            InputAction::Key{scan_code,pressed}=>{
                if navigation(*scan_code) {if *pressed {self.pending_key=Some(*scan_code);None}else if self.pending_key.take()==Some(*scan_code){Some(Step::Navigation{code:*scan_code})}else{None}}
                else {self.pending_key=None;if *pressed{Some(Step::TextRequired)}else{None}}
            },
            InputAction::PointerButton{x,y,button,pressed}=>{if *pressed{self.pending_button=Some((*x,*y,*button));None}else if self.pending_button.take()==Some((*x,*y,*button)){Some(Step::Click{x:*x,y:*y,button:*button,double:false})}else{self.notice="Ziehen ausgelassen; manuell erneut prüfen".into();None}},
            InputAction::Click{x,y,button}=>Some(Step::Click{x:*x,y:*y,button:*button,double:false}),
            InputAction::DoubleClick{x,y,button}=>Some(Step::Click{x:*x,y:*y,button:*button,double:true}),
            InputAction::Scroll{x,y,delta}=>Some(Step::Scroll{x:*x,y:*y,delta:*delta}),
            _=>None,
        };
        if let Some(step)=step {
            if step==Step::TextRequired && self.procedure.steps.last()==Some(&step){return;}
            if self.procedure.steps.len()<MAX_STEPS{self.procedure.steps.push(step);}
            if self.procedure.steps.len()>=MAX_STEPS{self.stop();self.notice="Limit von 200 Schritten erreicht; Aufnahme gestoppt".into();}
        }
    }
}
pub fn save(procedure:&Procedure)->Result<()> {
    if !cfg!(windows){bail!("Verschlüsselte Abläufe benötigen Windows DPAPI");}
    procedure.validate()?;
    let path=crate::security::app_data_file("teaching.dpapi")?;
    if let Some(parent)=path.parent(){std::fs::create_dir_all(parent)?;}
    let bytes=crate::security::protect_secret(&serde_json::to_vec(procedure)?)?;
    std::fs::write(path,bytes)?; Ok(())
}
pub fn load()->Result<Procedure> {
    if !cfg!(windows){bail!("Verschlüsselte Abläufe benötigen Windows DPAPI");}
    let path=crate::security::app_data_file("teaching.dpapi")?;
    if std::fs::metadata(&path)?.len()>128*1024{bail!("Ablaufdatei zu groß");}
    let procedure:Procedure=serde_json::from_slice(&crate::security::unprotect_secret(&std::fs::read(path)?)?)?;
    procedure.validate()?;Ok(procedure)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn secrets_and_clipboard_never_persist(){let id=Uuid::new_v4();let mut t=Teacher::default();t.start(id,(800,600));for a in [InputAction::TypeText{text:"secret-password".into()},InputAction::ClipboardFiles{paths:vec!["sensitive".into()]},InputAction::ClipboardDownload{directory:"private".into()},InputAction::Key{scan_code:0x1e,pressed:true},InputAction::MovePointer{x:1,y:2}]{t.observe(id,&a,Some((800,600)));}assert_eq!(t.procedure.steps,vec![Step::TextRequired]);assert!(!serde_json::to_string(&t.procedure).unwrap().contains("secret-password"));}
    #[test] fn isolated_and_bounded(){let id=Uuid::new_v4();let mut t=Teacher::default();t.start(id,(800,600));let a=InputAction::Click{x:1,y:1,button:MouseButton::Left};t.observe(Uuid::new_v4(),&a,Some((800,600)));assert!(t.procedure.steps.is_empty());for _ in 0..400{t.observe(id,&a,Some((800,600)));}assert_eq!(t.procedure.steps.len(),MAX_STEPS);assert!(t.session.is_none());}
    #[test] fn dimensions_stop_recording_and_block_replay(){let id=Uuid::new_v4();let mut t=Teacher::default();t.start(id,(800,600));t.observe(id,&InputAction::Screenshot,Some((801,600)));assert!(t.session.is_none());assert!(t.procedure.actions(&Step::TextRequired,(801,600),"").is_err());}
    #[test] fn only_balanced_navigation_survives(){let id=Uuid::new_v4();let mut t=Teacher::default();t.start(id,(800,600));t.observe(id,&InputAction::Key{scan_code:0x0f,pressed:true},Some((800,600)));assert!(t.procedure.steps.is_empty());t.observe(id,&InputAction::Key{scan_code:0x0f,pressed:false},Some((800,600)));let actions=t.procedure.actions(&t.procedure.steps[0],(800,600),"").unwrap();assert!(matches!(actions.last(),Some(InputAction::Key{pressed:false,..})));t.stop();assert!(t.pending_key.is_none());assert!(t.procedure.actions(&Step::Navigation{code:0x1e},(800,600),"").is_err());}
}
