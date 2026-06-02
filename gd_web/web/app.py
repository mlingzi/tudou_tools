import os, json, uuid, re, sqlite3, time, pymysql, traceback, logging
import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect
from flask_socketio import SocketIO, emit
from pymysql.cursors import DictCursor

# ==========================================
# 核心配置区
# ==========================================
DEBUG_MODE = True  # 【Debug 开关】生产环境请改为 False
USE_MYSQL = False
MYSQL_CONF = {'host': '10.2.16.120', 'user': 'tudou', 'password': 'Meng1998', 'database': 'event_manager', 'port': 3306}
SQLITE_PATH = 'test_database.db'

AGENT_TOKEN = "Sysmon-EDR-Super-Secret-Token-2026"  # Agent 鉴权 Token
WEB_ADMIN_PWD = "admin"                             # Web 控制台登录密码

# 缓存区
ACTIVE_HOSTS = {} 
ORG_CACHE = []

# ==========================================
# 初始化 Flask 与日志系统
# ==========================================
app = Flask(__name__)
# SECRET_KEY 不仅用于 SocketIO，也是 Session 登录态加密的必须配置
app.config['SECRET_KEY'] = 'event_998_super_secret_key_2026'
socketio = SocketIO(app, cors_allowed_origins="*")

# 配置专业日志管理器
log_level = logging.DEBUG if DEBUG_MODE else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SysmonBackend")


# ==========================================
# 安全拦截装饰器
# ==========================================
def require_agent_token(f):
    """拦截非法的 Agent 数据上报和配置拉取请求"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header != f"Bearer {AGENT_TOKEN}":
            logger.warning(f"🚨 拦截到非法 Agent 请求 (未授权 Token): {request.remote_addr}")
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    """拦截未登录就访问 Web 控制台和 Web API 的请求"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated


# ==========================================
# 基础功能与数据库逻辑
# ==========================================
def simplify(text):
    if not text: return ""
    text = str(text).strip().lower()
    text = text.replace('（', '(').replace('）', ')')
    text = re.sub(r'[^\u4e00-\u9fa5a-zA-Z0-9]', '', text)
    return text

def init_excel_cache():
    global ORG_CACHE
    if not os.path.exists('zuzhijiagou.xlsx'):
        logger.warning("⚠️ 警告: 未找到 zuzhijiagou.xlsx")
        return
    try:
        df = pd.read_excel('zuzhijiagou.xlsx').fillna('')
        ORG_CACHE = []
        for _, row in df.iterrows():
            feature = str(row.iloc[7]).strip() if len(row) > 7 else ""
            if feature and feature not in ['无', '-', 'nan']:
                ORG_CACHE.append({
                    'feature_simple': simplify(feature),
                    'biz_domain': str(row.iloc[5]) if len(row) > 5 else "",
                    'it_dept': str(row.iloc[6]) if len(row) > 6 else ""
                })
        logger.info(f"✅ Excel 加载成功：{len(ORG_CACHE)} 条规则")
    except Exception as e:
        logger.error(f"❌ Excel 加载失败: {e}", exc_info=DEBUG_MODE)

def get_db_connection(use_default_db=True):
    if USE_MYSQL:
        params = {
            'host': MYSQL_CONF['host'],
            'user': MYSQL_CONF['user'],
            'password': MYSQL_CONF['password'],
            'port': MYSQL_CONF['port'],
            'charset': 'utf8mb4',
            'cursorclass': DictCursor,
            'connect_timeout': 10
        }
        if use_default_db:
            params['database'] = MYSQL_CONF['database']
        return pymysql.connect(**params)
    else:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = lambda c, r: {col[0]: r[i] for i, col in enumerate(c.description)}
        return conn

def init_db():
    if USE_MYSQL:
        try:
            conn = get_db_connection(use_default_db=False)
            with conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_CONF['database']}` CHARACTER SET utf8mb4")
            conn.close()
        except Exception as e:
            logger.warning(f"⚠️ 数据库创建阶段提示: {e}")

    conn = get_db_connection(use_default_db=True)
    try:
        cursor = conn.cursor()
        # 事件管理表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR(36) PRIMARY KEY, 
                is_pinned BOOLEAN DEFAULT 0, 
                risk_analysis TEXT, root_cause TEXT, disposal TEXT, advice TEXT, 
                is_violation VARCHAR(10), resp_unit VARCHAR(255), 
                biz_domain VARCHAR(255), it_dept VARCHAR(255), 
                handler VARCHAR(255), remark TEXT, 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Sysmon 日志主表
        auto_inc = "AUTO_INCREMENT" if USE_MYSQL else "AUTOINCREMENT"
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS sysmon_logs (
                id INTEGER PRIMARY KEY {auto_inc},
                hostname VARCHAR(100), event_type VARCHAR(20), event_id VARCHAR(10),
                time_created VARCHAR(50), image TEXT, process_id VARCHAR(20),
                user TEXT, protocol VARCHAR(10), src_ip VARCHAR(50),
                dst_ip VARCHAR(50), dst_port VARCHAR(10), query_name TEXT,
                details_json TEXT, created_at TIMESTAMP
            )
        """)
        
        # 探针策略配置表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sysmon_config (
                hostname VARCHAR(100) PRIMARY KEY, 
                config_text TEXT, 
                collect_all BOOLEAN DEFAULT 1, 
                event_ids VARCHAR(255) DEFAULT '1,3,22', 
                command VARCHAR(50) DEFAULT ''
            )
        """)
        
        # 动态创建时间索引（支撑高级检索秒开）
        try:
            cursor.execute("CREATE INDEX idx_time_created ON sysmon_logs (time_created)")
        except Exception:
            pass # 索引已存在时忽略报错
            
        conn.commit()
        logger.info("✅ 数据库表初始化、索引及连接测试完成")
    finally:
        conn.close()

def get_p(): return "%s" if USE_MYSQL else "?"

def parse_sysmon_xml(xml_str):
    try:
        if not xml_str: return None
        xml_str = re.sub(r'\sxmlns=[\'"][^\'"]+[\'"]', '', xml_str)
        xml_str = re.sub(r'<\?xml.*\?>', '', xml_str)
        root = ET.fromstring(xml_str)
        system = root.find("System")
        event_id = system.find("EventID").text
        raw_time = system.find("TimeCreated").attrib.get("SystemTime", "")
        try:
            ts_str = raw_time.split('.')[0].replace('T', ' ')
            dt_obj = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            time_created = (dt_obj + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            time_created = raw_time.replace('T', ' ').split('.')[0]
            
        data_dict = {}
        event_data = root.find("EventData")
        if event_data is not None:
            for data in event_data.findall("Data"):
                name = data.attrib.get("Name")
                data_dict[name] = data.text if data.text else "-"
        raw_computer = system.find("Computer").text or ""
        short_hostname = raw_computer.split('.')[0].upper()                
        res = {
            "hostname": system.find("Computer").text,
            "event_id": event_id, "time_created": time_created,
            "image": data_dict.get("Image", "-"), "user": data_dict.get("User", "-"),
            "process_id": data_dict.get("ProcessId", "-"), "dst_ip": data_dict.get("DestinationIp", "-"),
            "dst_port": data_dict.get("DestinationPort", "-"), "protocol": data_dict.get("Protocol", "-"),
            "event_type": "Other", "query_name": "-", "details_json": json.dumps(data_dict, ensure_ascii=False)
        }
        
        if event_id == '1': res.update({"query_name": data_dict.get("CommandLine", "-"), "event_type": "Process"})
        elif event_id == '3': res.update({"query_name": data_dict.get("DestinationHostname", "-"), "event_type": "Network"})
        elif event_id == '22': res.update({"query_name": data_dict.get("QueryName", "-"), "dst_ip": data_dict.get("QueryResults", "-"), "event_type": "DNS"})
        elif event_id in ['11', '23', '26']: res.update({"query_name": data_dict.get("TargetFilename", "-"), "event_type": "File"})
        return res
    except Exception as e:
        logger.debug(f"⚠️ XML 解析失败: {e} | 数据片段: {xml_str[:100]}...") 
        return None

# ==========================================
# 调试路由：查看系统运行状态
# ==========================================
@app.route('/api/debug/status')
def debug_status():
    if not DEBUG_MODE:
        return jsonify({"status": "error", "message": "DEBUG_MODE is disabled."}), 403
    return jsonify({
        "status": "success",
        "database": "MySQL" if USE_MYSQL else "SQLite",
        "active_hosts_count": len(ACTIVE_HOSTS),
        "server_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


# ==========================================
# 【网页端】前端页面路由 (均需登录)
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_ADMIN_PWD:
            session['logged_in'] = True
            return redirect('/')
        return "<h3 style='color:red; text-align:center; margin-top:50px;'>密码错误!</h3>", 401
        
    # 极简炫酷登录页
    return '''
    <div style="display:flex; justify-content:center; align-items:center; height:100vh; background:#f0f2f5; font-family:sans-serif;">
        <form method="post" style="background:#fff; padding:40px; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.1); text-align:center;">
            <h2 style="margin-bottom:30px; color:#333;">EDR 控制台登录</h2>
            <input type="password" name="password" placeholder="请输入管理员密码" style="width:100%; padding:10px; margin-bottom:20px; border:1px solid #ddd; border-radius:5px; font-size:16px;">
            <button type="submit" style="width:100%; padding:10px; background:#0d6efd; color:#fff; border:none; border-radius:5px; font-size:16px; cursor:pointer;">登 录</button>
        </form>
    </div>
    '''

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY is_pinned DESC, created_at DESC")
    res = cursor.fetchall()
    conn.close()
    return render_template('index.html', events=res)

@app.route('/logs')
@login_required
def logs_page(): 
    return render_template('logs.html')

@app.route('/host_logs')
@login_required
def host_logs_page(): 
    return render_template('host_logs.html')


# ==========================================
# 【Agent端】通信与上报接口 (均需 Token 鉴权)
# ==========================================
@app.route('/api/agent/heartbeat', methods=['POST'])
@require_agent_token
def agent_heartbeat():
    h = request.json.get('hostname')
    if h: 
        ACTIVE_HOSTS[h] = {"time": time.time(), "ip": request.remote_addr}
        logger.debug(f"💓 [心跳] 收到主机心跳: {h} ({request.remote_addr})")
    return jsonify({"status": "success"})

@app.route('/api/agent/domains')
@require_agent_token
def agent_get_domains():
    h = request.args.get('hostname')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT event_ids, command FROM sysmon_config WHERE hostname = {get_p()}", (h,))
    cfg = cursor.fetchone()
    conn.close()
    
    res_data = {"event_ids": cfg['event_ids'] if cfg else "1,3,22", "command": cfg['command'] if cfg else ""}
    logger.debug(f"📡 [Agent 拉取配置] 主机: {h} | 下发配置: {res_data}")
    return jsonify(res_data)

@app.route('/api/agent/logs', methods=['POST'])
@require_agent_token
def receive_agent_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        raw_data = request.get_data()
        json_str = raw_data.decode('utf-8', errors='ignore')
        raw_list = json.loads(json_str)
        if isinstance(raw_list, dict): raw_list = [raw_list]
        
        logger.debug(f"📥 [Agent 上报] 收到日志数据，共 {len(raw_list)} 条记录")

        p = get_p()
        sql = f"INSERT INTO sysmon_logs (hostname, time_created, event_type, event_id, image, query_name, dst_ip, dst_port, user, process_id, details_json, created_at) VALUES ({p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p},{p})"
        now_bj = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
        
        success_count = 0
        for item in raw_list:
            parsed = parse_sysmon_xml(item.get('xml', ''))
            if parsed:
                cursor.execute(sql, (parsed['hostname'], parsed['time_created'], parsed['event_type'], parsed['event_id'], parsed['image'], parsed['query_name'], parsed['dst_ip'], parsed['dst_port'], parsed['user'], parsed['process_id'], parsed['details_json'], now_bj))
                success_count += 1
                
        conn.commit()
        logger.debug(f"✅ [日志入库] 成功存入 {success_count} / {len(raw_list)} 条")
        return jsonify({"status": "success", "count": success_count})
        
    except Exception as e:
        logger.error(f"❌ [日志接收报错]: {e}", exc_info=DEBUG_MODE)
        return jsonify({"status": "error", "message": str(e)}), 500
    finally: 
        conn.close()


# ==========================================
# 【网页端】API 接口 (供前端 JS 调用，均需登录)
# ==========================================
@app.route('/api/web/logs', methods=['GET'])
@login_required
def get_web_logs():
    """支持多维度高级过滤的动态日志检索接口"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        h = request.args.get('hostname', '')
        event_id = request.args.get('event_id', '')
        start_time = request.args.get('start_time', '')
        end_time = request.args.get('end_time', '')
        keyword = request.args.get('keyword', '')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 100))
        
        p = get_p()
        # 将前端传来的主机名也统一截断并转大写
        h = h.split('.')[0].upper() if h else ''
        
        # 使用 LIKE '主机名%'，这样既能查出新入库的 CHERY，也能查出老库里的 CHERY.local
        where_clauses = [f"hostname LIKE {p}"]
        params = [f"{h}%"]
        
        if event_id:
            where_clauses.append(f"event_id = {p}")
            params.append(event_id)
        if start_time:
            where_clauses.append(f"time_created >= {p}")
            params.append(start_time)
        if end_time:
            where_clauses.append(f"time_created <= {p}")
            params.append(end_time)
        if keyword:
            where_clauses.append(f"(image LIKE {p} OR query_name LIKE {p} OR dst_ip LIKE {p} OR details_json LIKE {p})")
            params.extend([f"%{keyword}%"] * 4)
            
        where_sql = "WHERE " + " AND ".join(where_clauses)
        offset = (page - 1) * limit
        
        cursor.execute(f"SELECT COUNT(*) as total FROM sysmon_logs {where_sql}", tuple(params))
        total = cursor.fetchone()['total']
        
        cursor.execute(f"SELECT * FROM sysmon_logs {where_sql} ORDER BY time_created DESC LIMIT {limit} OFFSET {offset}", tuple(params))
        logs = cursor.fetchall()
        
        return jsonify({"status": "success", "total": total, "data": logs})
    except Exception as e:
        logger.error(f"❌ [Web 查日志失败]: {e}")
        return jsonify({"status": "error", "total": 0, "data": []})
    finally:
        conn.close()

@app.route('/api/web/hosts')
@login_required
def get_hosts():
    now = time.time()
    res = []
    for h, info in ACTIVE_HOSTS.items():
        res.append({"hostname": h, "ip": info['ip'], "status": "在线" if (now-info['time'])<=90 else "离线"})
    return jsonify({"status": "success", "data": res})

@app.route('/api/web/config', methods=['GET', 'POST'])
@login_required
def manage_config():
    h = request.args.get('hostname', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute(f"SELECT event_ids FROM sysmon_config WHERE hostname = {get_p()}", (h,))
        d = cursor.fetchone() or {"event_ids": ""}
        conn.close()
        return jsonify({"status": "success", "data": d})
        
    d = request.json
    event_ids = d.get('event_ids', '')
    logger.info(f"⚙️ [Web 修改配置] 主机: {h} | 修改 EventIDs: {event_ids}")
    
    sql = "INSERT INTO sysmon_config (hostname, event_ids, collect_all) VALUES (%s, %s, 1) ON DUPLICATE KEY UPDATE event_ids=VALUES(event_ids)" if USE_MYSQL else "INSERT INTO sysmon_config (hostname, event_ids, collect_all) VALUES (?, ?, 1) ON CONFLICT(hostname) DO UPDATE SET event_ids=excluded.event_ids"
    cursor.execute(sql, (h, event_ids))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/web/command', methods=['POST'])
@login_required
def send_command():
    h = request.json.get('hostname')
    cmd = request.json.get('command')
    logger.info(f"🛠️ [Web 下发指令] 主机: {h} | 指令: {cmd}")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"UPDATE sysmon_config SET command={get_p()} WHERE hostname={get_p()}", (cmd, h))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


# ==========================================
# 【工单模块】(用于 Web 页面 Socket 同步)
# ==========================================
@app.route('/api/events', methods=['POST'], strict_slashes=False)
@login_required
def create_event():
    conn = get_db_connection()
    cursor = conn.cursor()
    nid = str(uuid.uuid4())
    cursor.execute(f"INSERT INTO events (id, is_violation, remark) VALUES ({get_p()}, '否', '无')", (nid,))
    conn.commit()
    conn.close()
    
    logger.info(f"📝 [事件管理] 创建了新事件条目: {nid}")
    socketio.emit('refresh_all', {'reason': 'new_item'})
    return jsonify({"status": "success", "id": nid})

@app.route('/api/events/<event_id>', methods=['PUT', 'DELETE'], strict_slashes=False)
@login_required
def handle_event(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    res = {"status": "error"}
    
    if request.method == 'PUT':
        data = request.json
        f = [f"{k}={get_p()}" for k in data.keys()]
        v = list(data.values())
        v.append(event_id)
        cursor.execute(f"UPDATE events SET {', '.join(f)} WHERE id={get_p()}", tuple(v))
        conn.commit()
        socketio.emit('sync_input', {'event_id': event_id, 'data': data})
        res = {"status": "success"}
        
    elif request.method == 'DELETE':
        logger.info(f"🗑️ [事件管理] 删除了事件 {event_id}")
        cursor.execute(f"DELETE FROM events WHERE id={get_p()}", (event_id,))
        conn.commit()
        socketio.emit('refresh_all', {'reason': 'delete_item'})
        res = {"status": "success"}
        
    conn.close()
    return jsonify(res)

@app.route('/api/events/<event_id>/top', methods=['POST'], strict_slashes=False)
@login_required
def toggle_pin(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"UPDATE events SET is_pinned = NOT is_pinned WHERE id={get_p()}", (event_id,))
    conn.commit()
    conn.close()
    socketio.emit('refresh_all', {'reason': 'pin_change'})
    return jsonify({"status": "success"})

@socketio.on('typing')
def handle_typing(data):
    if not data or 'event_id' not in data or 'key' not in data: return
    emit('sync_input', {'event_id': data['event_id'], 'data': {data['key']: data.get('value', '')}}, broadcast=True, include_self=False)
    
@app.route('/api/agent/command/clear', methods=['POST'])
@require_agent_token
def clear_agent_command():
    """Agent 执行完指令后的回调，使用 Token 鉴权，负责清空数据库状态"""
    h = request.json.get('hostname')
    logger.info(f"🔄 [Agent 指令回执] 主机 {h} 已完成指令，正在重置服务端状态...")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    # 将该主机的 command 字段设为空
    cursor.execute(f"UPDATE sysmon_config SET command='' WHERE hostname={get_p()}", (h,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/web/logs/clear', methods=['POST'])
@login_required
def clear_sysmon_logs():
    """清理日志库接口：支持按主机或天数清理，或者全部清空"""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        data = request.json or {}
        h = data.get('hostname', '')
        days = data.get('days', 0)  # 传 0 代表无视时间
        
        p = get_p()
        query = "DELETE FROM sysmon_logs WHERE 1=1"
        params = []
        
        # 1. 如果传了主机名，只删该主机的
        if h:
            h = h.split('.')[0].upper()
            query += f" AND hostname LIKE {p}"
            params.append(f"{h}%")
            
        # 2. 如果传了天数（例如 7），删除 7 天前的旧日志
        if int(days) > 0:
            cutoff = (datetime.now() - timedelta(days=int(days))).strftime('%Y-%m-%d %H:%M:%S')
            query += f" AND time_created < {p}"
            params.append(cutoff)
            
        cursor.execute(query, tuple(params))
        conn.commit()
        count = cursor.rowcount
        
        logger.info(f"🗑️ [Web 日志清理] 条件: 主机={h}, 保留天数={days} | 成功清理了 {count} 条日志")
        return jsonify({"status": "success", "count": count})
    except Exception as e:
        logger.error(f"❌ [Web 日志清理失败]: {e}")
        return jsonify({"status": "error", "message": str(e)})
    finally:
        conn.close()    

# ==========================================
# 启动入口
# ==========================================
if __name__ == '__main__':
    logger.info("🚀 启动后端服务...")
    init_excel_cache()
    init_db()
    # 强制绑定 0.0.0.0，开发环境下可通过 DEBUG_MODE 控制日志详情
    socketio.run(app, host='0.0.0.0', port=136, debug=DEBUG_MODE, use_reloader=False)