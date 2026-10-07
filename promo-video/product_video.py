from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
import subprocess,json,textwrap
from cloudflare_voice import generate

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'product'
COPY={
 'de':[
  ('Ein Arbeitsplatz für Ihr IT-Team.','Mission Control bündelt Aufträge, Prüfungen und Betriebswissen.'),
  ('Remote-Aufträge bewusst freigeben.','SSH, SFTP und WinRM: Ziel und Auftrag vor der Ausführung prüfen.'),
  ('Vom Vorfall zum nächsten Schritt.','Der Recovery Agent führt durch Beschreibung, Generalprobe und Freigabe.'),
  ('Wiederherstellungspläne aktuell halten.','Änderungen erkennen und neue Generalproben vorbereiten.'),
  ('Wissen wiederverwenden.','Vormachen, Erfolgskriterien definieren und geprüfte Abläufe speichern.')],
 'en':[
  ('One workspace for your IT team.','Mission Control brings jobs, checks and operational knowledge together.'),
  ('Approve remote jobs deliberately.','SSH, SFTP and WinRM: review the target and job before execution.'),
  ('From incident to next step.','The Recovery Agent guides incident description, rehearsal and approval.'),
  ('Keep recovery plans current.','Identify changes and prepare fresh rehearsals.'),
  ('Make knowledge reusable.','Demonstrate steps, define success criteria and save reviewed workflows.')]
}
NARRATION={
 ('de',30):'Entdecken Sie Relayne. Mission Control bündelt Aufträge und Prüfungen für Ihr IT-Team. Mit den Remote-Werkzeugen prüfen Sie Ziel und Auftrag vor der Freigabe. Der Recovery Agent führt von der Störungsbeschreibung über die Generalprobe bis zum nächsten Schritt. Wiederherstellungspläne helfen, geprüfte Abläufe aktuell zu halten. Und mit Vormachen und Lernen wird Betriebswissen wiederverwendbar. Relayne: ein gemeinsamer Arbeitsplatz für Ihre IT.',
 ('en',30):'Discover Relayne. Mission Control brings jobs and checks together for your IT team. Remote tools let you review the target and job before approval. The Recovery Agent guides you from an incident description through rehearsal to the next step. Recovery plans help keep reviewed procedures current. Demonstrate and learn makes operational knowledge reusable. Relayne: one shared workspace for your IT team.',
 ('de',60):'Das ist Relayne, ein gemeinsamer Arbeitsplatz für IT-Teams und Dienstleister. In Mission Control planen Sie Aufträge, wählen Prüfungen aus und arbeiten mit gemeinsamem Betriebswissen. Die Remote-Werkzeuge unterstützen SSH, SFTP und WinRM. Vor der Ausführung prüfen Sie den Zielrechner und den Auftrag und geben den Schritt bewusst frei. Bei einer Störung führt der Recovery Agent durch einen strukturierten Ablauf: den Vorfall beschreiben, eine unterstützte Reparatur vorbereiten, die Generalprobe prüfen und den nächsten Schritt freigeben. Dafür sind eine geeignete Testumgebung und die passende Infrastruktur erforderlich. Wiederherstellungspläne helfen dabei, geprüfte Abläufe aktuell zu halten und nach Änderungen erneut zu erproben. Mit Vormachen und Lernen können Sie Schritte erfassen, Erfolgskriterien definieren und geprüfte Arbeitsabläufe speichern. Starten Sie mit einem konkreten Pilotfall und prüfen Sie, wie Relayne Ihr Team unterstützen kann.',
 ('en',60):'This is Relayne, a shared workspace for IT teams and service providers. Mission Control helps you plan jobs, choose checks and work with shared operational knowledge. Remote tools support SSH, SFTP and WinRM. Before execution, review the target computer and the job, then explicitly approve the step. When an incident occurs, the Recovery Agent guides a structured workflow: describe the issue, prepare a supported repair, review the rehearsal and approve the next step. These workflows require a suitable test environment and the appropriate infrastructure. Recovery plans help keep reviewed procedures current and support new rehearsals after changes. Demonstrate and learn lets you capture steps, define success criteria and save reviewed workflows. Start with a concrete pilot case, and evaluate how Relayne can support your team.'
}
FONT='C:/Windows/Fonts/segoeui.ttf'; BOLD='C:/Windows/Fonts/segoeuib.ttf'
def run(args): subprocess.run(['ffmpeg','-y','-loglevel','error']+args,check=True)
def duration(path): return float(json.loads(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration','-of','json',str(path)]))['format']['duration'])
def wrap(draw,text,xy,width,size,color,bold=False):
 f=ImageFont.truetype(BOLD if bold else FONT,size); line=''; y=xy[1]
 for word in text.split():
  proposal=(line+' '+word).strip()
  if draw.textlength(proposal,font=f)>width and line:
   draw.text((xy[0],y),line,font=f,fill=color); y+=size*1.35; line=word
  else: line=proposal
 if line: draw.text((xy[0],y),line,font=f,fill=color)
 return y+size*1.35
for lang in ['de','en']:
 for i,(title,caption) in enumerate(COPY[lang]):
  im=Image.new('RGB',(1920,1080),'#0b1422');d=ImageDraw.Draw(im)
  d.rounded_rectangle((60,65,112,117),12,fill='#42dfc6');d.text((73,66),'R',font=ImageFont.truetype(BOLD,35),fill='#0b1422')
  d.text((130,69),'RELAYNE',font=ImageFont.truetype(BOLD,34),fill='white')
  d.text((62,220),f'0{i+1} / 05',font=ImageFont.truetype(FONT,25),fill='#42dfc6')
  y=wrap(d,title,(60,285),430,47,'white',True)
  wrap(d,caption,(62,y+35),420,29,'#9daec5')
  shot=Image.open(OUT/f'{lang}-{i}.png').convert('RGB');shot.thumbnail((1283,850))
  im.paste(shot,(570,150));
  footer='Tatsächliche Softwareoberfläche · Produktüberblick' if lang=='de' else 'Actual software interface · Product overview'
  d.text((60,1022),footer,font=ImageFont.truetype(FONT,22),fill='#9daec5')
  im.save(OUT/f'card-{lang}-{i}.png')
 for seconds in [30,60]:
  audio=OUT/f'OpenAI-{lang}-{seconds}.mp3'
  if not audio.exists(): generate(NARRATION[(lang,seconds)],audio)
  clips=[]; length=seconds/5
  for i in range(5):
   clip=OUT/f'clip-{lang}-{seconds}-{i}.mp4';clips.append(clip)
   run(['-loop','1','-i',str(OUT/f'card-{lang}-{i}.png'),'-vf',f'fade=t=in:st=0:d=0.25,fade=t=out:st={length-0.25}:d=0.25','-t',str(length),'-r','25','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p',str(clip)])
  listing=OUT/f'list-{lang}-{seconds}.txt'; listing.write_text('\n'.join("file '"+p.as_posix()+"'" for p in clips))
  silent=OUT/f'Relayne-{lang.upper()}-{seconds}s-Software-Text.mp4'
  run(['-f','concat','-safe','0','-i',str(listing),'-c','copy','-movflags','+faststart',str(silent)])
  pace=max(1,duration(audio)/(seconds-0.5))
  final=OUT/f'Relayne-{lang.upper()}-{seconds}s-Software-OpenAI.mp4'
  run(['-i',str(silent),'-i',str(audio),'-af',f'atempo={pace},apad','-t',str(seconds),'-c:v','copy','-c:a','aac','-movflags','+faststart',str(final)])
  print('Created',final.name,'narration pace',round(pace,2),flush=True)
(OUT/'narration.json').write_text(json.dumps({f'{lang}-{seconds}':text for (lang,seconds),text in NARRATION.items()},ensure_ascii=False,indent=2),encoding='utf-8')
