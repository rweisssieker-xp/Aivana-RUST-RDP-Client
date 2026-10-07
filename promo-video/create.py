from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import subprocess, json, math

ROOT = Path(__file__).resolve().parent
SCENES = {
 'de': [
  ('Wenn Systeme ausfallen,', 'zählt jeder Schritt.', 'Wenn Systeme ausfallen, zählt jeder Schritt. Entdecken Sie Relayne.'),
  ('Remote-Zugriff.', 'Ein gemeinsamer Arbeitsplatz.', 'Verbinden Sie Remote-Zugriff über RDP und SSH mit gemeinsamem Betriebswissen.'),
  ('Reparaturen erproben.', 'Zuerst im Klon.', 'Erproben Sie unterstützte Reparaturabläufe zuerst im Klon und prüfen Sie das Ergebnis.'),
  ('Ergebnisse prüfen.', 'Produktion bewusst freigeben.', 'Nutzen Sie Prüfnachweise, um den nächsten Schritt in der Produktion bewusst freizugeben.'),
  ('Relayne', 'Für IT-Teams. Bereit für Ihren Pilotfall.', 'Relayne. Remote-Zugriff und geprüfte Wiederherstellungsabläufe. Starten Sie mit einem Pilotfall.')],
 'en': [
  ('When systems fail,', 'every step matters.', 'When systems fail, every step matters. Discover Relayne.'),
  ('Remote access.', 'One shared workspace.', 'Connect remote access through RDP and SSH with shared operational knowledge.'),
  ('Rehearse repairs.', 'Start with a clone.', 'Rehearse supported recovery workflows in a clone first, and verify the results.'),
  ('Verify the outcome.', 'Approve the production step.', 'Use recorded test evidence to make an informed decision before approving the production step.'),
  ('Relayne', 'For IT teams. Start with your pilot case.', 'Relayne. Remote access and verified recovery workflows. Start with your pilot case.')]
}
(ROOT/'script.json').write_text(json.dumps(SCENES,ensure_ascii=False,indent=2),encoding='utf-8')
FONT = 'C:/Windows/Fonts/segoeui.ttf'
BOLD = 'C:/Windows/Fonts/segoeuib.ttf'
def font(n,b=False): return ImageFont.truetype(BOLD if b else FONT,n)
def render(lang):
 frames=[]
 for i,(title,sub,voice) in enumerate(SCENES[lang]):
  im=Image.new('RGB',(1280,720),'#0b1422'); d=ImageDraw.Draw(im)
  for x in range(0,1280,64): d.line((x,0,x,720),fill='#101e30')
  for y in range(0,720,64): d.line((0,y,1280,y),fill='#101e30')
  d.rounded_rectangle((70,65,118,113),12,fill='#42dfc6'); d.text((82,65),'R',font=font(34,True),fill='#0b1422')
  d.text((135,72),'RELAYNE',font=font(26,True),fill='white')
  d.text((76,210),f'0{i+1} / 05',font=font(21),fill='#42dfc6')
  d.text((70,275),title,font=font(56,True),fill='white')
  d.text((72,355),sub,font=font(38),fill='#9daec5')
  steps= ['VERBINDEN','ERPROBEN','PRÜFEN','FREIGEBEN'] if lang=='de' else ['CONNECT','REHEARSE','VERIFY','APPROVE']
  for j,step in enumerate(steps):
   x=72+j*286
   d.rounded_rectangle((x,480,x+260,540),12,outline='#345063',width=2)
   d.text((x+18,497),step,font=font(20,True),fill='#42dfc6')
  footer= 'Produktkonzept · Unterstützte Abläufe und Infrastruktur vorausgesetzt' if lang=='de' else 'Product overview · Supported workflows and infrastructure required'
  d.text((72,645),footer,font=font(18),fill='#8091a8')
  path=ROOT/f'{lang}-{i}.png'; im.save(path); frames.append(path)
 segments=[]
 for i,path in enumerate(frames):
  wav=ROOT/f'{lang}-{i}.wav'
  probe=subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration','-of','json',str(wav)])
  duration=max(6,float(json.loads(probe)['format']['duration'])+0.7)
  out=ROOT/f'{lang}-{i}.mp4'; segments.append(out)
  vf=f"scale=1344:756,crop=1280:720:x='32+12*sin(t/3)':y=18,fade=t=in:st=0:d=0.35,fade=t=out:st={duration-0.35}:d=0.35"
  subprocess.run(['ffmpeg','-y','-loglevel','error','-loop','1','-i',str(path),'-i',str(wav),'-vf',vf,'-af','apad','-t',str(duration),'-r','25','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p','-c:a','aac','-ar','48000','-ac','2',str(out)],check=True)
 listing=ROOT/f'{lang}-concat.txt'; listing.write_text('\n'.join("file '"+p.as_posix()+"'" for p in segments),encoding='utf-8')
 subprocess.run(['ffmpeg','-y','-loglevel','error','-f','concat','-safe','0','-i',str(listing),'-c','copy','-movflags','+faststart',str(ROOT/f'Relayne-Promo-{lang.upper()}.mp4')],check=True)
 print(f'Created Relayne-Promo-{lang.upper()}.mp4',flush=True)
if __name__=='__main__':
 import sys
 if '--render' in sys.argv:
  for lang in SCENES: render(lang)
