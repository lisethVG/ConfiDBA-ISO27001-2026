import os, re, json, random, sqlite3, datetime as dt
from functools import wraps
from flask import Flask, request, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import oracledb
except ImportError:
    oracledb = None
app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("CONFIDBA_SECRET", "cambie-esta-clave-en-produccion")
DB = os.path.join(os.path.dirname(__file__), "confidba.db")
now = dt.datetime.now

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
def run(sql, a=()):
    with db() as c:
        cur = c.execute(sql, a); return [dict(r) for r in cur.fetchall()], cur.lastrowid
run("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT)")
run("CREATE TABLE IF NOT EXISTS empresas(id INTEGER PRIMARY KEY, uid INT, nombre TEXT, esquema TEXT)")
run("CREATE TABLE IF NOT EXISTS evals(id INTEGER PRIMARY KEY, eid INT, fecha TEXT, modo TEXT, det TEXT)")

from controles import RIES, CH, EVID, IP, TAREAS, SOD

def hint(e):
    m = str(e); t = m.splitlines()[0][:160]
    if "01017" in m: return "Usuario o contraseña incorrectos. ¿Creó el usuario con sql/02_usuario_auditor.sql?"
    if "DPY-6005" in m or "12541" in m or "refused" in m.lower(): return "No se encontró la base: revise que Oracle esté encendida y que el servidor y el puerto sean correctos."
    if "DPY-6001" in m or "12514" in m: return "El servicio no existe. En Oracle XE el servicio de la PDB es XEPDB1."
    return "No se pudo conectar: " + t

def evaluar_real(p, esquema, pesos):
    if not oracledb: raise RuntimeError("Falta instalar oracledb (pip install oracledb)")
    con = oracledb.connect(user=p["user"], password=p["password"], dsn=f"{p.get('host', 'localhost')}:{p.get('port', 1521)}/{p['service']}")
    out = []
    with con:
        cur = con.cursor()
        for cid, nom, qs, fn, exp, sug in CH:
            d = dict(id=cid, nombre=nom, explica=exp, sug=sug, peso=pesos.get(cid, 10), manual=None, nota="", auto=None, error=False)
            try:
                res = []; d["filas"] = []
                for sql in qs:
                    cur.execute(sql, s=esquema.upper()) if ":s" in sql else cur.execute(sql)
                    rows = cur.fetchall(); res.append(rows)
                    d["filas"].append(dict(cols=[x[0] for x in cur.description], n=len(rows), rows=[[str(c) for c in r] for r in rows[:10]]))
                d["auto"], d["hallazgo"] = fn(res)
                if d["auto"] is None: d["hallazgo"] += " (no aplica: sin datos que evaluar)"
            except Exception as e:
                d.update(auto=0.0, error=True, hallazgo="No se pudo evaluar: " + str(e).splitlines()[0][:120] + ". Se cuenta como 0; ajústelo manualmente si corresponde.")
            out.append(d)
    return out

def evaluar_demo(pesos, n_prev):
    # Cada corrida mejora un poco respecto de la anterior, para mostrar el avance en el historial
    rnd = random.Random(7); t = [rnd.random() for _ in CH]; p = min(0.95, 0.2 + 0.15 * n_prev); out = []
    for k, (cid, nom, qs, fn, exp, sug) in enumerate(CH):
        a = 1.0 if t[k] < p else (0.5 if t[k] < p + 0.15 else 0.0)
        out.append(dict(id=cid, nombre=nom, explica=exp, sug=sug, peso=pesos.get(cid, 10), manual=None, nota="", auto=a, error=False, hallazgo="Dato simulado."))
    return out

def calc(det):
    ef = [None if d["manual"] == "NA" else (d["manual"] if d["manual"] is not None else d["auto"]) for d in det]
    def rc(ids=None):
        s = n = 0
        for d, v in zip(det, ef):
            if v is None or (ids and d["id"] not in ids): continue
            s += v * d["peso"]; n += d["peso"]
        return round(100 * s / n, 1) if n else None
    rs = [dict(id=i, nombre=nm, inh=inh, rc=rc(ids), res=None if rc(ids) is None else round(inh * (1 - rc(ids) / 100), 1)) for i, nm, inh, ids in RIES]
    t = rc(); z = None if t is None else ("Verde" if t >= 70 else "Amarillo" if t >= 30 else "Rojo")
    inh = sum(r[2] for r in RIES) / len(RIES)
    return dict(rc=t, zona=z, riesgos=rs, ok=sum(1 for v in ef if v == 1), parcial=sum(1 for v in ef if v is not None and 0 < v < 1),
                falla=sum(1 for v in ef if v == 0), n=sum(1 for v in ef if v is not None), inh=round(inh, 1), res=None if t is None else round(inh * (1 - t / 100), 1))

def resumen(emp, ev, det, c, prev):
    if c["rc"] is None: return "No hay controles evaluables."
    s = f"El {ev['fecha'][:10]}, {emp['nombre']} cumple por completo {c['ok']} de {c['n']} controles de confidencialidad ({c['rc']}% de cumplimiento ponderado, zona {c['zona'].lower()}). El riesgo promedio pasa de {c['inh']} (sin controles) a {c['res']} con los controles actuales. "
    if prev:
        d = round(c["rc"] - prev, 1)
        s += f"Frente a la evaluación anterior {'mejoró' if d > 0 else 'empeoró' if d < 0 else 'se mantuvo'} ({d:+.1f} puntos). "
    pend = [d for d in det if (d["manual"] if d["manual"] not in (None, "NA") else d["auto"] or 0) < 1 and d["manual"] != "NA" and d["auto"] is not None][:3]
    if pend: s += "Principales brechas: " + "; ".join(f"{d['nombre']} ({d['hallazgo'].rstrip('.')})" for d in pend) + "."
    return s

def auth(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session: return jsonify(error="Inicie sesión"), 401
        return f(*a, **k)
    return w
def mia(eid):
    r, _ = run("SELECT * FROM empresas WHERE id=? AND uid=?", (eid, session["uid"]))
    return r[0] if r else None

@app.route("/")
def index(): return send_from_directory("static", "index.html")
@app.get("/api/catalogo")
@auth
def catalogo():
    return jsonify(ch=[dict(id=c[0], nombre=c[1], sql=c[2], explica=c[4], sug=c[5], **EVID.get(c[0], {})) for c in CH],
                   ries=[dict(id=r[0], nombre=r[1], inh=r[2], ctl=r[3], i=IP[k][0], p=IP[k][1]) for k, r in enumerate(RIES)], tareas=TAREAS, sod=SOD)
@app.post("/api/probar")
@auth
def probar():
    b = request.json
    try:
        if not oracledb: raise RuntimeError("Falta instalar oracledb")
        con = oracledb.connect(user=b["user"], password=b["password"], dsn=f"{b.get('host', 'localhost')}:{b.get('port', 1521)}/{b['service']}")
        with con:
            cur = con.cursor(); cur.execute("SELECT banner FROM v$version FETCH FIRST 1 ROWS ONLY"); return jsonify(ok=True, banner=cur.fetchone()[0])
    except Exception as ex: return jsonify(error=hint(ex)), 400
@app.post("/api/register")
def register():
    b = request.json; em = (b.get("email") or "").strip().lower()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", em) or len(b.get("password") or "") < 8: return jsonify(error="Correo válido y contraseña de 8+ caracteres"), 400
    try: _, uid = run("INSERT INTO users(email,pw) VALUES(?,?)", (em, generate_password_hash(b["password"])))
    except sqlite3.IntegrityError: return jsonify(error="Ese correo ya tiene cuenta: use la pestaña Ingresar."), 400
    session["uid"] = uid; return jsonify(email=em)
@app.post("/api/login")
def login():
    b = request.json; r, _ = run("SELECT * FROM users WHERE email=?", ((b.get("email") or "").strip().lower(),))
    if not r or not check_password_hash(r[0]["pw"], b.get("password") or ""): return jsonify(error="Correo o contraseña incorrectos. Si es su primera vez, use Crear cuenta."), 401
    session["uid"] = r[0]["id"]; return jsonify(email=r[0]["email"])
@app.post("/api/logout")
def logout(): session.clear(); return jsonify(ok=1)
@app.get("/api/me")
def me():
    if "uid" not in session: return jsonify(email=None)
    r, _ = run("SELECT email FROM users WHERE id=?", (session["uid"],)); return jsonify(email=r[0]["email"] if r else None)
@app.route("/api/empresas", methods=["GET", "POST"])
@auth
def empresas():
    if request.method == "POST":
        b = request.json; run("INSERT INTO empresas(uid,nombre,esquema) VALUES(?,?,?)", (session["uid"], b.get("nombre", "Empresa"), b.get("esquema") or "CONFI_LAB"))
    return jsonify(run("SELECT * FROM empresas WHERE uid=? ORDER BY id", (session["uid"],))[0])
@app.get("/api/empresas/<int:eid>/evals")
@auth
def evals(eid):
    if not mia(eid): return jsonify(error="No existe"), 404
    r, _ = run("SELECT id,fecha,modo,det FROM evals WHERE eid=? ORDER BY id", (eid,))
    return jsonify([dict(id=x["id"], fecha=x["fecha"], modo=x["modo"], rc=calc(json.loads(x["det"]))["rc"]) for x in r])
@app.post("/api/empresas/<int:eid>/run")
@auth
def correr(eid):
    e = mia(eid)
    if not e: return jsonify(error="No existe"), 404
    b = request.json; prev, _ = run("SELECT det FROM evals WHERE eid=? ORDER BY id DESC", (eid,))
    pesos = {d["id"]: d["peso"] for d in json.loads(prev[0]["det"])} if prev else {}
    try: det = evaluar_demo(pesos, len(prev)) if b.get("modo") == "demo" else evaluar_real(b, e["esquema"], pesos)
    except Exception as ex: return jsonify(error=hint(ex)), 400
    _, i = run("INSERT INTO evals(eid,fecha,modo,det) VALUES(?,?,?,?)", (eid, now().isoformat(timespec="seconds"), b.get("modo"), json.dumps(det)))
    return jsonify(id=i)
@app.route("/api/evals/<int:i>", methods=["GET", "PATCH"])
@auth
def ev(i):
    r, _ = run("SELECT * FROM evals WHERE id=?", (i,)); e = mia(r[0]["eid"]) if r else None
    if not e: return jsonify(error="No existe"), 404
    det = json.loads(r[0]["det"])
    if request.method == "PATCH":
        b = request.json
        for d in det:
            if d["id"] == b["id"]:
                if "manual" in b: d["manual"] = b["manual"]
                if "peso" in b: d["peso"] = max(1, float(b["peso"]))
                if "nota" in b: d["nota"] = b["nota"][:300]
        run("UPDATE evals SET det=? WHERE id=?", (json.dumps(det), i))
    c = calc(det); pr, _ = run("SELECT det FROM evals WHERE eid=? AND id<? ORDER BY id DESC", (e["id"], i))
    return jsonify(id=i, fecha=r[0]["fecha"], modo=r[0]["modo"], empresa=e["nombre"], det=det, calc=c, resumen=resumen(e, r[0], det, c, calc(json.loads(pr[0]["det"]))["rc"] if pr else None))

if __name__ == "__main__":
    print("ConfiDBA Studio en http://127.0.0.1:5000"); app.run(host="127.0.0.1", port=5000)
