import os, sqlite3, secrets
from datetime import date, datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, render_template_string, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB = os.environ.get("DATABASE_PATH", "sasman.db")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    c = g.pop("db", None)
    if c: c.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin');
    CREATE TABLE IF NOT EXISTS packages(id INTEGER PRIMARY KEY, name TEXT NOT NULL, speed_down INTEGER NOT NULL, speed_up INTEGER NOT NULL, days INTEGER NOT NULL DEFAULT 30, price REAL NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS subscribers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT, area TEXT, pppoe_username TEXT UNIQUE NOT NULL, pppoe_password TEXT NOT NULL, package_id INTEGER, start_date TEXT, end_date TEXT, status TEXT NOT NULL DEFAULT 'active', notes TEXT, created_at TEXT NOT NULL, FOREIGN KEY(package_id) REFERENCES packages(id));
    CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY, subscriber_id INTEGER NOT NULL, amount REAL NOT NULL, paid_at TEXT NOT NULL, note TEXT, FOREIGN KEY(subscriber_id) REFERENCES subscribers(id));
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
    """)
    c.commit()
    if not c.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD")
        if not password:
            password = secrets.token_urlsafe(12)
            print("\\nSASMAN FIRST ADMIN LOGIN")
            print("Username:", username)
            print("Temporary password:", password)
            print("Set ADMIN_PASSWORD and SECRET_KEY in production environment.\\n")
        c.execute("INSERT INTO admins(username,password_hash,role) VALUES(?,?,?)", (username, generate_password_hash(password), "admin"))
    if not c.execute("SELECT 1 FROM packages LIMIT 1").fetchone():
        c.executemany("INSERT INTO packages(name,speed_down,speed_up,days,price) VALUES(?,?,?,?,?)", [
            ("7 ميكا",7,7,30,30),("10 ميكا",10,10,30,35)])
    c.commit(); c.close()

init_db()

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("admin_id"): return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper

STYLE = """
<meta name='viewport' content='width=device-width, initial-scale=1'>
<style>
body{font-family:Arial,sans-serif;background:#f2f5f9;color:#172033;margin:0;direction:rtl}
header{background:#10213d;color:white;padding:16px 20px;display:flex;justify-content:space-between;align-items:center}
main{max-width:1150px;margin:22px auto;padding:0 14px}
.card{background:white;border-radius:12px;padding:18px;margin:12px 0;box-shadow:0 2px 12px #12203a0d}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}
.stat{font-size:25px;font-weight:bold;margin-top:8px}
input,select,textarea{box-sizing:border-box;width:100%;padding:11px;margin:6px 0 12px;border:1px solid #cbd5e1;border-radius:7px;background:white}
button,.btn{background:#1769aa;color:white;border:0;border-radius:7px;padding:10px 14px;cursor:pointer;text-decoration:none;display:inline-block}
.secondary{background:#53657d} .danger{background:#b42318}
table{width:100%;border-collapse:collapse;background:white}th,td{text-align:right;padding:10px;border-bottom:1px solid #e6ebf2;font-size:14px}
.tablewrap{overflow:auto}.muted{color:#637083}.flash{padding:10px;background:#fff0c2;border-radius:7px;margin:8px 0}
label{font-size:14px;font-weight:bold}
a{color:inherit}
</style>
"""
def page(title, body):
    return render_template_string(STYLE + """
    <header><div><b>SASMAN RADIUS Cloud</b><div style='font-size:12px'>إدارة المشتركين والاشتراكات</div></div>
    {% if session.get('admin_id') %}<nav><a href='{{ url_for("dashboard") }}'>الرئيسية</a>　<a href='{{ url_for("subscribers") }}'>المشتركون</a>　<a href='{{ url_for("packages") }}'>الباقات</a>　<a href='{{ url_for("logout") }}'>خروج</a></nav>{% endif %}</header>
    <main><h2>{{ title }}</h2>{% for m in get_flashed_messages() %}<div class='flash'>{{m}}</div>{% endfor %}""" + body + "</main>", title=title)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        row = db().execute("SELECT * FROM admins WHERE username=?", (request.form.get("username",""),)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password","")):
            session.clear(); session["admin_id"]=row["id"]; session["username"]=row["username"]; session["role"]=row["role"]
            return redirect(url_for("dashboard"))
        flash("بيانات الدخول غير صحيحة")
    return page("تسجيل الدخول", """
    <div class='card' style='max-width:420px;margin:30px auto'><form method='post'>
    <label>اسم المستخدم</label><input name='username' required autocomplete='username'>
    <label>كلمة المرور</label><input type='password' name='password' required autocomplete='current-password'>
    <button>دخول</button></form><p class='muted'>غيّر كلمة المرور الافتراضية قبل نشر النظام على الإنترنت.</p></div>""")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    c=db()
    total=c.execute("SELECT COUNT(*) n FROM subscribers").fetchone()["n"]
    today=date.today().isoformat()
    active=c.execute("SELECT COUNT(*) n FROM subscribers WHERE status='active' AND end_date>=?",(today,)).fetchone()["n"]
    expired=c.execute("SELECT COUNT(*) n FROM subscribers WHERE end_date<? OR status='expired'",(today,)).fetchone()["n"]
    soon=c.execute("SELECT COUNT(*) n FROM subscribers WHERE end_date BETWEEN ? AND ? AND status='active'",(today,(date.today()+timedelta(days=5)).isoformat())).fetchone()["n"]
    debt=c.execute("""SELECT COALESCE(SUM(p.price-COALESCE(x.paid,0)),0) v FROM subscribers s LEFT JOIN packages p ON p.id=s.package_id LEFT JOIN (SELECT subscriber_id,SUM(amount) paid FROM payments GROUP BY subscriber_id) x ON x.subscriber_id=s.id WHERE s.status!='deleted'""").fetchone()["v"]
    revenue=c.execute("SELECT COALESCE(SUM(amount),0) v FROM payments").fetchone()["v"]
    body="""<div class='grid'>"""+''.join(f"<div class='card'>{label}<div class='stat'>{val}</div></div>" for label,val in [("إجمالي المشتركين",total),("فعالون حسب التاريخ",active),("اشتراكات منتهية",expired),("تنتهي خلال 5 أيام",soon),("الديون التقديرية",f"{debt:.2f}"),("الدفعات المسجلة",f"{revenue:.2f}")])+"""</div><div class='card'><b>حالة الربط</b><p>ربط MikroTik غير مفعّل بعد. أضف إعدادات API آمنة واختبر الاتصال قبل تنفيذ أي تغيير على المشتركين.</p><p class='muted'>هذه النسخة الأولية لا تدّعي أن الحسابات أو حالات الاتصال متزامنة مع الراوتر.</p><a class='btn' href='/subscribers'>إدارة المشتركين</a></div>"""
    return page("لوحة التحكم",body)

@app.route("/subscribers")
@login_required
def subscribers():
    rows=db().execute("""SELECT s.*,p.name package_name,p.price FROM subscribers s LEFT JOIN packages p ON p.id=s.package_id WHERE s.status!='deleted' ORDER BY s.id DESC""").fetchall()
    trs=""
    for s in rows:
        days=""
        try: days=(date.fromisoformat(s["end_date"])-date.today()).days
        except: pass
        state="منتهي" if s["end_date"] and s["end_date"]<date.today().isoformat() else ("موقوف" if s["status"]=="suspended" else "فعال")
        trs+=f"<tr><td>{s['name']}</td><td>{s['pppoe_username']}</td><td>{s['package_name'] or '-'}</td><td>{s['end_date'] or '-'}</td><td>{days}</td><td>{state}</td><td><a class='btn' href='/subscriber/{s['id']}'>فتح</a></td></tr>"
    return page("المشتركون", """<div class='card'><a class='btn' href='/subscriber/new'>+ إضافة مشترك</a></div><div class='card tablewrap'><table><tr><th>الاسم</th><th>PPPoE</th><th>الباقة</th><th>الانتهاء</th><th>الأيام</th><th>الحالة المحلية</th><th></th></tr>"""+trs+"</table></div>")

@app.route("/subscriber/new", methods=["GET","POST"])
@app.route("/subscriber/<int:sid>/edit", methods=["GET","POST"])
@login_required
def subscriber_form(sid=None):
    c=db(); s=c.execute("SELECT * FROM subscribers WHERE id=?",(sid,)).fetchone() if sid else None
    pkgs=c.execute("SELECT * FROM packages ORDER BY speed_down").fetchall()
    if request.method=="POST":
        f=request.form
        try:
            start=f.get("start_date") or date.today().isoformat()
            end=f.get("end_date") or (date.fromisoformat(start)+timedelta(days=int(next((p["days"] for p in pkgs if str(p["id"])==f.get("package_id")),30)))).isoformat()
            values=(f["name"].strip(),f.get("phone",""),f.get("area",""),f["pppoe_username"].strip(),f.get("pppoe_password",""),int(f["package_id"]) if f.get("package_id") else None,start,end,f.get("status","active"),f.get("notes",""))
            if sid:
                c.execute("""UPDATE subscribers SET name=?,phone=?,area=?,pppoe_username=?,pppoe_password=?,package_id=?,start_date=?,end_date=?,status=?,notes=? WHERE id=?""",values+(sid,))
                action="تعديل مشترك"
            else:
                c.execute("""INSERT INTO subscribers(name,phone,area,pppoe_username,pppoe_password,package_id,start_date,end_date,status,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",values+(datetime.utcnow().isoformat(),))
                action="إضافة مشترك"
            c.execute("INSERT INTO audit(actor,action,details,created_at) VALUES(?,?,?,?)",(session.get("username"),action,f["pppoe_username"],datetime.utcnow().isoformat()))
            c.commit(); flash("تم حفظ البيانات محلياً في قاعدة SASMAN. لم يتم إرسالها إلى MikroTik."); return redirect(url_for("subscribers"))
        except sqlite3.IntegrityError:
            flash("اسم مستخدم PPPoE مستخدم مسبقاً.")
        except Exception as e:
            flash("تعذر الحفظ؛ تحقق من الحقول والتواريخ.")
    val=lambda key,default="": (s[key] if s and s[key] is not None else default)
    opts="".join(f"<option value='{p['id']}' {'selected' if s and s['package_id']==p['id'] else ''}>{p['name']} — {p['speed_down']}/{p['speed_up']} Mbps — {p['price']}</option>" for p in pkgs)
    return page("إضافة مشترك" if not s else "تعديل مشترك",f"""<div class='card'><form method='post'>
    <label>الاسم</label><input name='name' required value='{val('name')}'>
    <label>رقم الهاتف</label><input name='phone' value='{val('phone')}'>
    <label>المنطقة</label><input name='area' value='{val('area')}'>
    <label>اسم مستخدم PPPoE</label><input name='pppoe_username' required value='{val('pppoe_username')}'>
    <label>كلمة مرور PPPoE</label><input name='pppoe_password' required value='{val('pppoe_password')}'>
    <label>الباقة</label><select name='package_id'>{opts}</select>
    <label>تاريخ البداية</label><input type='date' name='start_date' value='{val('start_date',date.today().isoformat())}'>
    <label>تاريخ الانتهاء (اتركه فارغاً ليحسب النظام المدة)</label><input type='date' name='end_date' value='{val('end_date')}'>
    <label>الحالة</label><select name='status'><option value='active'>فعال</option><option value='suspended' {'selected' if val('status')=='suspended' else ''}>موقوف</option></select>
    <label>ملاحظات</label><textarea name='notes'>{val('notes')}</textarea>
    <button>حفظ</button> <a class='btn secondary' href='/subscribers'>رجوع</a></form></div>""")

@app.route("/subscriber/<int:sid>")
@login_required
def subscriber_detail(sid):
    c=db(); s=c.execute("SELECT s.*,p.name package_name,p.price FROM subscribers s LEFT JOIN packages p ON p.id=s.package_id WHERE s.id=?",(sid,)).fetchone()
    if not s: return "غير موجود",404
    pays=c.execute("SELECT * FROM payments WHERE subscriber_id=? ORDER BY id DESC",(sid,)).fetchall()
    paid=sum(p["amount"] for p in pays); debt=(s["price"] or 0)-paid
    payrows="".join(f"<tr><td>{p['paid_at']}</td><td>{p['amount']:.2f}</td><td>{p['note'] or ''}</td></tr>" for p in pays)
    return page("ملف المشترك",f"""<div class='card'><p><b>الاسم:</b> {s['name']}</p><p><b>PPPoE:</b> {s['pppoe_username']}</p><p><b>الباقة:</b> {s['package_name'] or '-'}</p><p><b>الانتهاء:</b> {s['end_date'] or '-'}</p><p><b>المدفوع المسجل:</b> {paid:.2f} | <b>الدين التقديري:</b> {debt:.2f}</p>
    <a class='btn' href='/subscriber/{sid}/edit'>تعديل</a>
    <form method='post' action='/subscriber/{sid}/payment' style='margin-top:18px'><label>تسجيل دفعة</label><input name='amount' type='number' step='0.01' min='0.01' required placeholder='المبلغ'><input name='note' placeholder='ملاحظة / طريقة الدفع'><button>تسجيل الدفعة</button></form>
    <form method='post' action='/subscriber/{sid}/renew'><label>تجديد الاشتراك</label><input name='days' type='number' min='1' value='30' required><button>تجديد محلي</button><p class='muted'>التجديد هنا يحدث قاعدة SASMAN فقط، إلى أن نكمل ربط الراوتر.</p></form>
    </div><div class='card'><h3>سجل الدفعات</h3><table><tr><th>التاريخ</th><th>المبلغ</th><th>ملاحظة</th></tr>{payrows}</table></div>""")

@app.route("/subscriber/<int:sid>/payment",methods=["POST"])
@login_required
def payment(sid):
    try:
        amount=float(request.form["amount"])
        if amount<=0: raise ValueError()
        c=db(); c.execute("INSERT INTO payments(subscriber_id,amount,paid_at,note) VALUES(?,?,?,?)",(sid,amount,datetime.utcnow().isoformat(timespec="seconds"),request.form.get("note","")))
        c.commit(); flash("تم تسجيل الدفعة.")
    except: flash("تعذر تسجيل الدفعة؛ تحقق من المبلغ.")
    return redirect(url_for("subscriber_detail",sid=sid))

@app.route("/subscriber/<int:sid>/renew",methods=["POST"])
@login_required
def renew(sid):
    try:
        c=db(); s=c.execute("SELECT * FROM subscribers WHERE id=?",(sid,)).fetchone()
        if not s: return "غير موجود",404
        days=max(1,min(365,int(request.form["days"])))
        base=date.fromisoformat(s["end_date"]) if s["end_date"] and s["end_date"]>=date.today().isoformat() else date.today()
        end=(base+timedelta(days=days)).isoformat()
        c.execute("UPDATE subscribers SET start_date=?,end_date=?,status='active' WHERE id=?",(date.today().isoformat(),end,sid))
        c.execute("INSERT INTO audit(actor,action,details,created_at) VALUES(?,?,?,?)",(session.get("username"),"تجديد محلي",f"{s['pppoe_username']} حتى {end}",datetime.utcnow().isoformat()))
        c.commit(); flash("تم تحديث تاريخ الاشتراك في قاعدة SASMAN فقط. لم يُعدّل MikroTik بعد.")
    except: flash("تعذر التجديد.")
    return redirect(url_for("subscriber_detail",sid=sid))

@app.route("/packages",methods=["GET","POST"])
@login_required
def packages():
    c=db()
    if request.method=="POST":
        try:
            c.execute("INSERT INTO packages(name,speed_down,speed_up,days,price) VALUES(?,?,?,?,?)",(request.form["name"],int(request.form["down"]),int(request.form["up"]),int(request.form["days"]),float(request.form["price"])))
            c.commit(); flash("تمت إضافة الباقة.")
        except: flash("تعذر إضافة الباقة؛ تحقق من القيم.")
    rows=c.execute("SELECT * FROM packages ORDER BY id").fetchall()
    trs="".join(f"<tr><td>{p['name']}</td><td>{p['speed_down']}/{p['speed_up']}</td><td>{p['days']}</td><td>{p['price']:.2f}</td></tr>" for p in rows)
    return page("الباقات",f"""<div class='card'><form method='post'><label>اسم الباقة</label><input name='name' required><div class='grid'><div><label>تنزيل Mbps</label><input name='down' type='number' min='1' required></div><div><label>رفع Mbps</label><input name='up' type='number' min='1' required></div><div><label>المدة بالأيام</label><input name='days' type='number' min='1' value='30' required></div><div><label>السعر</label><input name='price' type='number' step='0.01' min='0' required></div></div><button>إضافة باقة</button></form></div><div class='card'><table><tr><th>الباقة</th><th>السرعة تنزيل/رفع</th><th>المدة</th><th>السعر</th></tr>{trs}</table></div>""")

@app.route("/health")
def health():
    return {"status":"ok","app":"SASMAN RADIUS Cloud","mode":"local-database-only","router_connected":False}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8080")), debug=False)
