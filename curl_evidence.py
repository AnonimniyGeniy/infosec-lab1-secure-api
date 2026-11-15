"""Выполняет настоящие curl-запросы; сохраняет только обезличенные HTTP-пакеты."""
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
from pathlib import Path
import bcrypt
from werkzeug.serving import make_server
from src.app import create_app

with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    database = temporary / 'curl.sqlite'
    secret = os.urandom(32).hex()
    password = os.urandom(16).hex()
    app = create_app({'JWT_SECRET': secret, 'DATABASE': str(database)})
    with sqlite3.connect(database) as connection:
        connection.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',
                           ('curl-demo', bcrypt.hashpw(password.encode(),bcrypt.gensalt(rounds=12))))
    server = make_server('127.0.0.1',0,app)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    base=f'http://127.0.0.1:{server.server_port}'
    transcript=[]
    checks=[]
    token=None
    def request(name,method,path,body=None,authenticated=False,expected=200):
        payload=temporary/'payload.json'
        headerfile=temporary/'headers.txt'
        headers=['Content-Type: application/json']
        if authenticated: headers.append('Authorization: Bearer '+token)
        headerfile.write_text('\n'.join(headers)+'\n')
        args=['curl','--silent','--show-error','--include','--request',method,'--header','@'+str(headerfile)]
        if body is not None:
            payload.write_text(json.dumps(body))
            args.extend(['--data-binary','@'+str(payload)])
        args.append(base+path)
        response=subprocess.run(args,check=True,capture_output=True,text=True).stdout
        rawheaders,rawbody=response.split('\n\n',1)
        status=int(rawheaders.splitlines()[0].split()[1])
        parsed=json.loads(rawbody)
        redacted=response.replace(password,'[REDACTED demo password]')
        if token: redacted=redacted.replace(token,'[REDACTED JWT]')
        if 'access_token' in parsed: redacted=redacted.replace(parsed['access_token'],'[REDACTED JWT]')
        request_text=method+' '+path+' HTTP/1.1\nHost: '+base.removeprefix('http://')+'\nContent-Type: application/json\n'
        if authenticated: request_text+='Authorization: Bearer [REDACTED JWT]\n'
        if body is not None: request_text+='\n'+json.dumps(body,ensure_ascii=False).replace(password,'[REDACTED demo password]')+'\n'
        transcript.append('=== '+name+' ===\n'+request_text+'\n'+redacted+'\n')
        assert status==expected,(name,status,expected)
        checks.append({'check':name,'method':method,'path':path,'status':status,'expected':expected,'passed':True})
        return parsed
    try:
        request('login_bad','POST','/auth/login',{'username':'curl-demo','password':'invalid-demo-password'},expected=401)
        token=request('login_good','POST','/auth/login',{'username':'curl-demo','password':password})['access_token']
        request('get_without_jwt','GET','/api/data',expected=401)
        request('get_with_jwt','GET','/api/data',authenticated=True)
        created=request('post_note','POST','/api/notes',{'text':'Curl functional verification'},True,201)
        notes=request('read_created_note','GET','/api/data',authenticated=True)
        assert any(note['id']==created['id'] and note['text']=='Curl functional verification' for note in notes['notes'])
        artifacts=Path('artifacts');artifacts.mkdir(exist_ok=True)
        (artifacts/'curl-http-redacted.txt').write_text('curl functional verification; actual HTTP requests, demo credentials/JWT redacted\n\n'+'\n'.join(transcript))
        (artifacts/'curl-summary.json').write_text(json.dumps(checks,indent=2))
        print(json.dumps({'curl_checks_passed':len(checks),'statuses':[check['status'] for check in checks]}))
    finally: server.shutdown()
