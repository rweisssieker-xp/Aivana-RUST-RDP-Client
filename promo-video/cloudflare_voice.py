"""Generate Relayne narration using the existing Wrangler credential, never logging it."""
import json, os, pathlib, tomllib, urllib.request, urllib.error, base64

ROOT=pathlib.Path(__file__).resolve().parent
ACCOUNT='4b0fd8180d954c7db4b4a0bacbe2594b'
def generate(text, destination, voice='nova'):
    config=pathlib.Path(os.environ['APPDATA'])/'xdg.config/.wrangler/config/default.toml'
    token=tomllib.loads(config.read_text())['oauth_token']
    payload={'model':'openai/tts-1-hd','input':{'text':text,'voice':voice,'response_format':'mp3','speed':1}}
    req=urllib.request.Request(f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/ai/run',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=90) as response:
            data=response.read(); kind=response.headers.get('Content-Type','')
    except urllib.error.HTTPError as error:
        message=json.loads(error.read())
        raise RuntimeError(f'Cloudflare HTTP {error.code}: '+json.dumps(message.get('errors',[]))) from None
    if 'json' in kind:
        result=json.loads(data)
        if not result.get('success',True): raise RuntimeError(json.dumps(result.get('errors',[])))
        result=result.get('result',result)
        if isinstance(result,dict) and 'result' in result:
            result=result['result']
        audio=result.get('audio') if isinstance(result,dict) else None
        if not audio: raise RuntimeError('Response contains no audio; keys: '+str(list(result) if isinstance(result,dict) else type(result)))
        if audio.startswith('https://'):
            with urllib.request.urlopen(audio,timeout=90) as response: data=response.read()
        else: data=base64.b64decode(audio.split(',')[-1])
    pathlib.Path(destination).write_bytes(data)
    print('Audio saved:',pathlib.Path(destination).name, len(data),'bytes')
if __name__=='__main__':
    generate('Wenn Systeme ausfallen, zählt jeder Schritt. Relayne verbindet Remote-Zugriff mit geprüften Wiederherstellungsabläufen. Reparaturen zuerst im Klon erproben, Ergebnisse prüfen und den nächsten Schritt bewusst freigeben.',ROOT/'OpenAI-Cloudflare-DE-Probe.mp3')
