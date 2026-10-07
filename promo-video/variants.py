from create import ROOT, SCENES, render
import subprocess,json

def run(args): subprocess.run(['ffmpeg','-y','-loglevel','error']+args,check=True)
for lang in ['de','en']:
 source=ROOT/f'Relayne-Promo-{lang.upper()}.mp4'
 duration=float(json.loads(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration','-of','json',str(source)]))['format']['duration'])
 speed=duration/30
 run(['-i',str(source),'-vf',f'setpts=PTS/{speed}','-af',f'atempo={speed}','-t','30','-c:v','libx264','-preset','fast','-pix_fmt','yuv420p','-c:a','aac','-movflags','+faststart',str(ROOT/f'Relayne-{lang.upper()}-30s-Voice.mp4')])
 run(['-i',str(ROOT/f'Relayne-{lang.upper()}-30s-Voice.mp4'),'-an','-c:v','copy','-movflags','+faststart',str(ROOT/f'Relayne-{lang.upper()}-30s-Text.mp4')])
 extended=[]
 for i in range(5):
  out=ROOT/f'{lang}-long-{i}.mp4'; extended.append(out)
  wav=ROOT/f'{lang}-long-{i}.wav'
  spoken=float(json.loads(subprocess.check_output(['ffprobe','-v','error','-show_entries','format=duration','-of','json',str(wav)]))['format']['duration'])
  pace=max(1,spoken/11.5)
  run(['-loop','1','-i',str(ROOT/f'{lang}-{i}.png'),'-i',str(wav),'-vf',"scale=1344:756,crop=1280:720:x='32+12*sin(t/3)':y=18,fade=t=in:st=0:d=0.4,fade=t=out:st=11.6:d=0.4",'-af',f'atempo={pace},apad','-t','12','-r','25','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p','-c:a','aac','-ar','48000','-ac','2',str(out)])
 listing=ROOT/f'{lang}-long.txt'; listing.write_text('\n'.join("file '"+p.as_posix()+"'" for p in extended),encoding='utf-8')
 run(['-f','concat','-safe','0','-i',str(listing),'-c','copy','-movflags','+faststart',str(ROOT/f'Relayne-{lang.upper()}-60s-Voice.mp4')])
 print(f'{lang}: all three variants created',flush=True)
