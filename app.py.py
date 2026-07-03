from flask import Flask, jsonify, request
from flask_cors import CORS
import pymysql, uuid
from datetime import datetime, date, timedelta

app = Flask(__name__)
CORS(app)

# ─── MySQL Connection Config ───────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     3306,
    "user":     "root",        
    "password": "",            
    "database": "darkwatch",
    "charset":  "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

def serialize_row(row):
    """Helper to convert date, datetime, and decimal objects to JSON-serializable formats."""
    if not row:
        return row
    for k in list(row.keys()):
        if isinstance(row[k], (date, datetime)):
            row[k] = str(row[k])
        elif row[k].__class__.__name__ == 'Decimal':
            row[k] = float(row[k])
    return row

def serialize_rows(rows):
    return [serialize_row(r) for r in rows]

# ─── MONITORING & DASHBOARD ───────────────────────────────────────────────

@app.route("/api/health")
def health():
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS t FROM information_schema.tables WHERE table_schema='darkwatch'")
        tables = cur.fetchone()["t"]
        conn.close()
        return jsonify({"status": "online", "database": "MySQL", "tables": tables,
                        "time": datetime.now().isoformat(), "project": "DarkWatch Pro"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/dashboard")
def dashboard():
    conn = get_db(); cur = conn.cursor()
    def q(sql): cur.execute(sql); return cur.fetchone()

    stats = {
        "total_breaches":   q("SELECT COUNT(*) v FROM breach_record")["v"],
        "active_breaches":  q("SELECT COUNT(*) v FROM breach_record WHERE status='active'")["v"],
        "critical_alerts":  q("SELECT COUNT(*) v FROM risk_alert WHERE severity='Critical' AND is_resolved=0")["v"],
        "total_records":    int(q("SELECT COALESCE(SUM(records_exposed),0) v FROM breach_record")["v"]),
        "active_actors":    q("SELECT COUNT(*) v FROM threat_actor WHERE status='active'")["v"],
        "total_creds":      int(q("SELECT COALESCE(SUM(record_count),0) v FROM leaked_credential")["v"]),
        "open_alerts":      q("SELECT COUNT(*) v FROM risk_alert WHERE is_resolved=0")["v"],
        "total_iocs":       q("SELECT COUNT(*) v FROM ioc")["v"],
        "for_sale_creds":   q("SELECT COUNT(*) v FROM leaked_credential WHERE is_for_sale=1")["v"],
        "total_ransom_paid":float(q("SELECT COALESCE(SUM(ransom_paid),0) v FROM breach_record WHERE ransom_paid IS NOT NULL")["v"]),
        "active_malwares":  q("SELECT COUNT(*) v FROM malware_sample WHERE is_active=1")["v"],
    }

    cur.execute("SELECT severity, COUNT(*) AS cnt FROM breach_record GROUP BY severity ORDER BY cnt DESC")
    sev_dist = cur.fetchall()

    cur.execute("""SELECT i.name AS industry, COUNT(*) AS cnt
        FROM breach_record b JOIN industry i ON i.industry_id=b.industry_id
        GROUP BY i.name ORDER BY cnt DESC LIMIT 8""")
    ind_dist = cur.fetchall()

    cur.execute("SELECT breach_type, COUNT(*) AS cnt FROM breach_record GROUP BY breach_type ORDER BY cnt DESC")
    type_dist = cur.fetchall()

    trend = []
    for i in range(30):
        d = (date.today() - timedelta(days=29-i)).strftime("%Y-%m-%d")
        cur.execute("SELECT COUNT(*) AS cnt FROM breach_record WHERE discovered_date <= %s", (d,))
        trend.append({"date": d, "count": cur.fetchone()["cnt"]})

    cur.execute("""SELECT b.breach_id, b.organization, b.severity, b.breach_type,
        b.records_exposed, b.discovered_date, b.status, b.ransom_demanded,
        i.name AS industry, co.country_name AS country, ta.alias AS actor
        FROM breach_record b
        LEFT JOIN industry i ON i.industry_id=b.industry_id
        LEFT JOIN country co ON co.country_code=b.country_code
        LEFT JOIN threat_actor ta ON ta.actor_id=b.actor_id
        ORDER BY b.discovered_date DESC LIMIT 10""")
    recent = serialize_rows(cur.fetchall())

    cur.execute("""SELECT ta.alias, co.country_name, ta.actor_type, ta.sophistication, ta.status,
        COUNT(DISTINCT b.breach_id) AS breach_count,
        COALESCE(SUM(b.records_exposed),0) AS total_stolen
        FROM threat_actor ta
        LEFT JOIN country co ON co.country_code=ta.country_code
        LEFT JOIN breach_record b ON b.actor_id=ta.actor_id
        GROUP BY ta.actor_id ORDER BY breach_count DESC LIMIT 6""")
    top_actors = serialize_rows(cur.fetchall())

    cur.execute("""SELECT ra.*, b.organization FROM risk_alert ra
        JOIN breach_record b ON b.breach_id=ra.breach_id
        WHERE ra.is_resolved=0 ORDER BY ra.created_at DESC LIMIT 8""")
    recent_alerts = serialize_rows(cur.fetchall())

    conn.close()
    return jsonify({"stats": stats, "severity_dist": sev_dist, "industry_dist": ind_dist,
                    "breach_type_dist": type_dist, "breach_trend": trend,
                    "recent_breaches": recent, "top_actors": top_actors,
                    "recent_alerts": recent_alerts})

# ─── BREACH RECORDS CRUD & SEARCH ──────────────────────────────────────────

@app.route("/api/breaches", methods=["GET", "POST"])
def breaches():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; bid = str(uuid.uuid4())
        cur.execute("SELECT industry_id FROM industry WHERE name=%s", (d.get("industry","Technology"),))
        row = cur.fetchone(); ind_id = row["industry_id"] if row else None
        cur.execute("""INSERT INTO breach_record(breach_id,organization,industry_id,country_code,
            breach_date,discovered_date,breach_type,records_exposed,data_types,severity,status,description)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (bid, d["organization"], ind_id, d.get("country_code"), d.get("breach_date"),
             date.today().strftime("%Y-%m-%d"), d.get("breach_type","Data Exfiltration"),
             int(d.get("records_exposed",0)), d.get("data_types"), d.get("severity","Medium"), d.get("status","active"), d.get("description","")))
        conn.commit(); conn.close(); return jsonify({"breach_id": bid}), 201

    sev = request.args.get("severity",""); btype = request.args.get("type",""); q = request.args.get("q","")
    sql = """SELECT b.*, i.name AS industry, co.country_name AS country,
             ta.alias AS actor_name, ds.name AS source_name
             FROM breach_record b
             LEFT JOIN industry i ON i.industry_id=b.industry_id
             LEFT JOIN country co ON co.country_code=b.country_code
             LEFT JOIN threat_actor ta ON ta.actor_id=b.actor_id
             LEFT JOIN dark_source ds ON ds.source_id=b.source_id"""
    conds, params = [], []
    if sev:   conds.append("b.severity=%s");    params.append(sev)
    if btype: conds.append("b.breach_type=%s"); params.append(btype)
    if q:     conds.append("(b.organization LIKE %s OR b.description LIKE %s)"); params.extend([f"%{q}%", f"%{q}%"])
    if conds: sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY b.discovered_date DESC"
    cur.execute(sql, params); rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/breaches/<bid>", methods=["GET", "PUT", "DELETE"])
def breach_detail(bid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM breach_record WHERE breach_id=%s", (bid,))
        conn.commit(); conn.close(); return jsonify({"ok": True})
    
    if request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE breach_record SET organization=%s, breach_type=%s, severity=%s, 
                    status=%s, records_exposed=%s, description=%s WHERE breach_id=%s""",
                    (d["organization"], d["breach_type"], d["severity"], d["status"], int(d["records_exposed"]), d["description"], bid))
        conn.commit(); conn.close(); return jsonify({"ok": True})

    cur.execute("""SELECT b.*, i.name AS industry, co.country_name,
        ta.alias AS actor_name, ds.name AS source_name
        FROM breach_record b
        LEFT JOIN industry i ON i.industry_id=b.industry_id
        LEFT JOIN country co ON co.country_code=b.country_code
        LEFT JOIN threat_actor ta ON ta.actor_id=b.actor_id
        LEFT JOIN dark_source ds ON ds.source_id=b.source_id
        WHERE b.breach_id=%s""", (bid,))
    b = serialize_row(cur.fetchone())
    if not b: conn.close(); return jsonify({"error":"not found"}), 404
    
    cur.execute("SELECT * FROM leaked_credential WHERE breach_id=%s", (bid,))
    creds = serialize_rows(cur.fetchall())
    cur.execute("SELECT * FROM risk_alert WHERE breach_id=%s ORDER BY created_at DESC", (bid,))
    alerts = serialize_rows(cur.fetchall())
    cur.execute("SELECT * FROM ioc WHERE breach_id=%s", (bid,))
    iocs = serialize_rows(cur.fetchall())
    conn.close()
    return jsonify({"breach": b, "credentials": creds, "alerts": alerts, "iocs": iocs})

# ─── THREAT ACTORS CRUD & SEARCH ───────────────────────────────────────────

@app.route("/api/actors", methods=["GET", "POST"])
def actors():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; aid = str(uuid.uuid4())
        cur.execute("""INSERT INTO threat_actor (actor_id, alias, real_name, country_code, actor_type, 
                    motivation, sophistication, active_since, last_seen, status, description)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (aid, d["alias"], d.get("real_name"), d.get("country_code"), d["actor_type"],
                     d.get("motivation"), d.get("sophistication"), d.get("active_since"), d.get("last_seen"), d.get("status","active"), d.get("description")))
        conn.commit(); conn.close(); return jsonify({"actor_id": aid}), 201

    q = request.args.get("q","")
    sql = """SELECT ta.*, co.country_name, co.is_high_risk,
        COUNT(DISTINCT b.breach_id) AS breach_count,
        COALESCE(SUM(b.records_exposed),0) AS total_stolen,
        COUNT(DISTINCT am.malware_id) AS malware_count
        FROM threat_actor ta
        LEFT JOIN country co ON co.country_code=ta.country_code
        LEFT JOIN breach_record b ON b.actor_id=ta.actor_id
        LEFT JOIN actor_malware am ON am.actor_id=ta.actor_id"""
    params = []
    if q:
        sql += " WHERE ta.alias LIKE %s OR ta.real_name LIKE %s"
        params.extend([f"%{q}%", f"%{q}%"])
    sql += " GROUP BY ta.actor_id ORDER BY breach_count DESC"
    cur.execute(sql, params); rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/actors/<aid>", methods=["GET", "PUT", "DELETE"])
def actor_detail(aid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM threat_actor WHERE actor_id=%s", (aid,))
        conn.commit(); conn.close(); return jsonify({"ok": True})
    if request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE threat_actor SET alias=%s, country_code=%s, actor_type=%s, 
                    sophistication=%s, status=%s, description=%s WHERE actor_id=%s""",
                    (d["alias"], d.get("country_code"), d["actor_type"], d["sophistication"], d["status"], d["description"], aid))
        conn.commit(); conn.close(); return jsonify({"ok": True})

    cur.execute("""SELECT ta.*, co.country_name FROM threat_actor ta
        LEFT JOIN country co ON co.country_code=ta.country_code WHERE ta.actor_id=%s""", (aid,))
    a = serialize_row(cur.fetchone())
    if not a: conn.close(); return jsonify({"error":"not found"}), 404
    
    cur.execute("""SELECT b.organization,b.breach_type,b.severity,b.records_exposed,b.breach_date,
        i.name AS industry FROM breach_record b
        LEFT JOIN industry i ON i.industry_id=b.industry_id
        WHERE b.actor_id=%s ORDER BY b.breach_date DESC LIMIT 12""", (aid,))
    brs = serialize_rows(cur.fetchall())
    
    cur.execute("""SELECT m.*,am.relationship,am.first_used FROM malware_sample m
        JOIN actor_malware am ON am.malware_id=m.malware_id WHERE am.actor_id=%s""", (aid,))
    mwrs = serialize_rows(cur.fetchall())
    
    cur.execute("SELECT * FROM ioc WHERE actor_id=%s LIMIT 15", (aid,))
    iocs = serialize_rows(cur.fetchall())
    conn.close()
    return jsonify({"actor": a, "breaches": brs, "malwares": mwrs, "iocs": iocs})

# ─── LEAKED CREDENTIALS CRUD & SEARCH ──────────────────────────────────────

@app.route("/api/credentials", methods=["GET", "POST"])
def credentials():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; cid = str(uuid.uuid4())
        cur.execute("""INSERT INTO leaked_credential (cred_id, breach_id, email_domain, credential_type, 
                    record_count, is_verified, is_for_sale, asking_price) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (cid, d["breach_id"], d["email_domain"], d["credential_type"], int(d.get("record_count", 0)),
                     int(d.get("is_verified", 0)), int(d.get("is_for_sale", 0)), d.get("asking_price")))
        conn.commit(); conn.close(); return jsonify({"cred_id": cid}), 201

    q = request.args.get("q", "")
    sql = """SELECT lc.*, b.organization, b.severity FROM leaked_credential lc
             JOIN breach_record b ON b.breach_id=lc.breach_id"""
    params = []
    if q:
        sql += " WHERE lc.email_domain LIKE %s OR b.organization LIKE %s"
        params.extend([f"%{q}%", f"%{q}%"])
    sql += " ORDER BY lc.record_count DESC"
    cur.execute(sql, params); rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/credentials/<cid>", methods=["PUT", "DELETE"])
def credential_detail(cid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM leaked_credential WHERE cred_id=%s", (cid,))
    elif request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE leaked_credential SET email_domain=%s, credential_type=%s, 
                    record_count=%s, is_verified=%s, is_for_sale=%s, asking_price=%s WHERE cred_id=%s""",
                    (d["email_domain"], d["credential_type"], int(d["record_count"]), int(d["is_verified"]), int(d["is_for_sale"]), d["asking_price"], cid))
    conn.commit(); conn.close(); return jsonify({"ok": True})

# ─── MALWARE LIBRARY CRUD & SEARCH ──────────────────────────────────────────

@app.route("/api/malware", methods=["GET", "POST"])
def malware():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; mid = str(uuid.uuid4())
        cur.execute("""INSERT INTO malware_sample (malware_id, name, family, malware_type, target_os, 
                    target_sector, is_active, description, hash_md5, hash_sha256) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (mid, d["name"], d.get("family"), d["malware_type"], d.get("target_os"), d.get("target_sector"),
                     int(d.get("is_active", 1)), d.get("description"), d.get("hash_md5"), d.get("hash_sha256")))
        conn.commit(); conn.close(); return jsonify({"malware_id": mid}), 201

    q = request.args.get("q", "")
    sql = """SELECT m.*, GROUP_CONCAT(DISTINCT ta.alias SEPARATOR ', ') AS actor_names
        FROM malware_sample m
        LEFT JOIN actor_malware am ON am.malware_id=m.malware_id
        LEFT JOIN threat_actor ta ON ta.actor_id=am.actor_id"""
    params = []
    if q:
        sql += " WHERE m.name LIKE %s OR m.family LIKE %s OR m.target_os LIKE %s"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    sql += " GROUP BY m.malware_id ORDER BY m.last_seen DESC"
    cur.execute(sql, params); rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/malware/<mid>", methods=["PUT", "DELETE"])
def malware_detail(mid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM malware_sample WHERE malware_id=%s", (mid,))
    elif request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE malware_sample SET name=%s, family=%s, malware_type=%s, 
                    target_os=%s, target_sector=%s, is_active=%s, description=%s WHERE malware_id=%s""",
                    (d["name"], d["family"], d["malware_type"], d["target_os"], d["target_sector"], int(d["is_active"]), d["description"], mid))
    conn.commit(); conn.close(); return jsonify({"ok": True})

# ─── IOC DATABASE CRUD & SEARCH ────────────────────────────────────────────

@app.route("/api/iocs", methods=["GET", "POST"])
def iocs():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; iid = str(uuid.uuid4())
        cur.execute("""INSERT INTO ioc (ioc_id, breach_id, actor_id, ioc_type, value, confidence, is_active, tags, tlp_level) 
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (iid, d.get("breach_id"), d.get("actor_id"), d["ioc_type"], d["value"], int(d.get("confidence", 50)),
                     int(d.get("is_active", 1)), d.get("tags"), d.get("tlp_level", "AMBER")))
        conn.commit(); conn.close(); return jsonify({"ioc_id": iid}), 201

    q = request.args.get("q", "")
    sql = """SELECT i.*, b.organization, ta.alias AS actor_name
        FROM ioc i LEFT JOIN breach_record b ON b.breach_id=i.breach_id
        LEFT JOIN threat_actor ta ON ta.actor_id=i.actor_id"""
    params = []
    if q:
        sql += " WHERE i.value LIKE %s OR i.tags LIKE %s OR i.ioc_type=%s"
        params.extend([f"%{q}%", f"%{q}%", q])
    sql += " ORDER BY i.last_seen DESC LIMIT 150"
    cur.execute(sql, params); rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/iocs/<iid>", methods=["PUT", "DELETE"])
def ioc_detail(iid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM ioc WHERE ioc_id=%s", (iid,))
    elif request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE ioc SET value=%s, ioc_type=%s, confidence=%s, 
                    is_active=%s, tlp_level=%s WHERE ioc_id=%s""",
                    (d["value"], d["ioc_type"], int(d["confidence"]), int(d["is_active"]), d["tlp_level"], iid))
    conn.commit(); conn.close(); return jsonify({"ok": True})

# ─── DARK SOURCES CRUD ─────────────────────────────────────────────────────

@app.route("/api/sources", methods=["GET", "POST"])
def sources():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; sid = str(uuid.uuid4())
        cur.execute("""INSERT INTO dark_source (source_id, name, source_type, url_pattern, tor_address, language, reliability, is_active, description) 
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (sid, d["name"], d["source_type"], d.get("url_pattern"), d.get("tor_address"), d.get("language", "English"),
                     int(d.get("reliability", 5)), int(d.get("is_active", 1)), d.get("description")))
        conn.commit(); conn.close(); return jsonify({"source_id": sid}), 201

    cur.execute("""SELECT s.*, COUNT(b.breach_id) AS breach_count
        FROM dark_source s LEFT JOIN breach_record b ON b.source_id=s.source_id
        GROUP BY s.source_id ORDER BY breach_count DESC""")
    rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/sources/<sid>", methods=["PUT", "DELETE"])
def source_detail(sid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM dark_source WHERE source_id=%s", (sid,))
    elif request.method == "PUT":
        d = request.json
        cur.execute("""UPDATE dark_source SET name=%s, source_type=%s, reliability=%s, 
                    is_active=%s, description=%s WHERE source_id=%s""",
                    (d["name"], d["source_type"], int(d["reliability"]), int(d["is_active"]), d["description"], sid))
    conn.commit(); conn.close(); return jsonify({"ok": True})

# ─── ANALYSTS SECTION CRUD ─────────────────────────────────────────────────

@app.route("/api/analysts", methods=["GET", "POST"])
def analysts_route():
    conn = get_db(); cur = conn.cursor()
    if request.method == "POST":
        d = request.json; anid = str(uuid.uuid4())
        cur.execute("""INSERT INTO analyst (analyst_id, name, email, role, specialization) 
                    VALUES (%s,%s,%s,%s,%s)""", (anid, d["name"], d["email"], d.get("role", "analyst"), d.get("specialization")))
        conn.commit(); conn.close(); return jsonify({"analyst_id": anid}), 201

    cur.execute("SELECT * FROM analyst ORDER BY created_at DESC")
    rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/analysts/<anid>", methods=["PUT", "DELETE"])
def analyst_detail(anid):
    conn = get_db(); cur = conn.cursor()
    if request.method == "DELETE":
        cur.execute("DELETE FROM analyst WHERE analyst_id=%s", (anid,))
    elif request.method == "PUT":
        d = request.json
        cur.execute("UPDATE analyst SET name=%s, email=%s, role=%s, specialization=%s WHERE analyst_id=%s",
                    (d["name"], d["email"], d["role"], d["specialization"], anid))
    conn.commit(); conn.close(); return jsonify({"ok": True})

# ─── SYSTEM RISK ALERTS ────────────────────────────────────────────────────

@app.route("/api/alerts")
def fetch_unresolved_alerts():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""SELECT ra.*, b.organization, an.name AS analyst_name
        FROM risk_alert ra JOIN breach_record b ON b.breach_id=ra.breach_id
        LEFT JOIN analyst an ON an.analyst_id=ra.analyst_id
        WHERE ra.is_resolved=0 ORDER BY ra.created_at DESC""")
    rows = serialize_rows(cur.fetchall()); conn.close()
    return jsonify(rows)

@app.route("/api/alerts/<aid>/resolve", methods=["POST"])
def resolve_alert(aid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE risk_alert SET is_resolved=1, resolved_at=NOW() WHERE alert_id=%s", (aid,))
    conn.commit(); conn.close(); return jsonify({"ok": True})

@app.route("/api/industries")
def industries():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""SELECT i.*, COUNT(b.breach_id) AS breach_count,
        COALESCE(SUM(b.records_exposed),0) AS total_records
        FROM industry i LEFT JOIN breach_record b ON b.industry_id=i.industry_id
        GROUP BY i.industry_id ORDER BY breach_count DESC""")
    rows = cur.fetchall(); conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    print("\n🕵️  DarkWatch Pro Engine Operating Setup Running — Port 5000")
    app.run(debug=True, port=5000)