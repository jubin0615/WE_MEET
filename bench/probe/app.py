"""Inert synthetic source fixtures. Never import or run this application."""
from flask import Flask, request, send_file, render_template_string
from flask_cors import CORS
from markupsafe import Markup, escape
from sqlalchemy import text
from werkzeug.utils import secure_filename
import os, subprocess, pickle, yaml, jwt, requests

app = Flask(__name__)
# GT: P01 VS-06 vulnerable
SECRET_KEY = "dev"
# GT: P02 VS-06 vulnerable
CORS(app)
# GT: P03 VS-01 vulnerable
OPENAI_KEY = "oa_9fK2xQ7pL4tZ8rV1nB6cH3jD"
# GT: P04 VS-01 vulnerable
aws = "AKIAABCDEFGHIJKLMNOP"
# GT: P05 VS-01 vulnerable
url = "postgresql://sample:synthetic-password@localhost/demo"

def queries(db):
    q = request.args.get('q')
    # GT: P06 VS-05 vulnerable
    db.execute(f"SELECT * FROM notes WHERE id={q}")
    query = "select * from notes where id='" + q + "'"
    # GT: P07 VS-05 vulnerable
    db.execute(query)
    # GT: P08 VS-05 vulnerable
    db.execute("DELETE FROM notes WHERE id=%s" % q)
    # GT: P09 VS-05 vulnerable
    db.execute(text("UPDATE notes SET title='{}'".format(q)))
    # GT: S01 VS-05 safe
    db.execute("SELECT * FROM notes WHERE id=?", (q,))

def dangerous():
    q = request.args.get('q')
    # GT: P10 VS-05 vulnerable
    render_template_string('<p>' + q)
    # GT: P11 VS-05 vulnerable
    Markup('<p>%s' % q)
    # GT: P12 VS-05 vulnerable
    subprocess.run('echo ' + q, shell=True)
    # GT: P13 VS-05 vulnerable
    eval(q)
    # GT: P14 VS-05 vulnerable
    send_file(os.path.join('files', q))
    # GT: P15 VS-05 vulnerable
    requests.get(q)
    # GT: P16 VS-05 vulnerable
    pickle.loads(request.data)
    # GT: P17 VS-05 vulnerable
    yaml.load(q, Loader=yaml.Loader)
    # GT: P18 VS-02 vulnerable
    jwt.decode(q, options={'verify_signature': False})
    f = request.files['file']
    # GT: P19 VS-05 vulnerable
    f.save(os.path.join('uploads', f.filename))
    # GT: S02 VS-05 safe
    Markup(escape(q))
    # GT: S03 VS-05 safe
    subprocess.run(['echo', q], shell=False)
    # GT: S04 VS-05 safe
    send_file(os.path.join('files', secure_filename(q)))
    # GT: S05 VS-05 safe
    requests.get('https://example.invalid')
    # GT: S06 VS-05 safe
    yaml.safe_load(q)
    # GT: S07 VS-02 safe
    jwt.decode(q, signing_key, algorithms=['HS256'])
    # GT: S08 VS-05 safe
    f.save(os.path.join('uploads', secure_filename(f.filename)))

@app.get('/admin/users')
# GT: P20 VS-02 vulnerable
def admin_users():
    return 'users'

@app.get('/orders/<int:order_id>')
# GT: P21 VS-02 vulnerable
def order(order_id):
    return db.query(order_id)

def cookie(response):
    # GT: P22 VS-06 vulnerable
    response.set_cookie('role', request.args.get('role'))
    # GT: S09 VS-06 safe
    response.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')

# GT: P23 VS-06 vulnerable
app.run(debug=True, host='0.0.0.0')
# GT: S10 VS-06 safe
app.run(debug=False)

@app.get('/admin/safe')
@admin_required
# GT: S11 VS-02 safe
def safe_admin():
    return 'users'

@app.get('/orders/<int:order_id>')
@login_required
# GT: S12 VS-02 safe
def safe_order(order_id):
    return db.query(order_id).filter(owner_id=current_user.id)

# GT: S13 VS-01 safe
OPENAI_KEY = os.environ['OPENAI_KEY']
# GT: S14 VS-06 safe
SECRET_KEY = os.environ['SESSION_SECRET']
# GT: S15 VS-06 safe
CORS(app, origins=['https://example.invalid'])
