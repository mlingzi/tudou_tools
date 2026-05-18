const API_HEADERS = { 'Content-Type': 'application/json' };

// 1. 初始化 Socket.IO 连接
const socket = io();

/**
 * WebSocket 监听：实时同步输入内容
 */
socket.on('sync_input', (msg) => {
    const form = document.querySelector(`.live-form[data-id="${msg.event_id}"]`);
    if (!form) return;

    Object.keys(msg.data).forEach(key => {
        const input = form.querySelector(`[name="${key}"]`);
        // 关键：只有当该输入框不是当前用户正在操作（获得焦点）的那个时，才同步数据
        if (input && input !== document.activeElement) {
            input.value = msg.data[key];

            // 如果是违规状态下拉框，同步更新颜色
            if (key === 'is_violation') {
                input.className = 'status-select ' + (msg.data[key] === '是' ? 'text-red' : 'text-green');
            }
        }
    });
});

/**
 * WebSocket 监听：全局结构刷新
 */
socket.on('refresh_all', (msg) => {
    console.log('数据结构变动，刷新页面...', msg.reason);
    window.location.reload();
});

/**
 * 实时按键输入监听
 */
document.addEventListener('input', (e) => {
    if (e.target.classList.contains('live-input') || e.target.classList.contains('status-select')) {
        const form = e.target.closest('.live-form');
        if (form) {
            const id = form.getAttribute('data-id');
            const key = e.target.name;
            const value = e.target.value;

            socket.emit('typing', {
                event_id: id,
                key: key,
                value: value
            });
        }
    }
});

/**
 * 自动保存数据 (失去焦点时持久化到数据库)
 */
function saveData(el) {
    const form = el.closest('.live-form');
    const id = form.getAttribute('data-id');
    const formData = {};
    new FormData(form).forEach((v, k) => formData[k] = v);

    fetch(`/api/events/${id}`, {
        method: 'PUT',
        headers: API_HEADERS,
        body: JSON.stringify(formData)
    }).then(res => {
        if (res.ok) {
            const tag = form.querySelector('.save-tag');
            if (tag) {
                tag.style.opacity = 1;
                setTimeout(() => tag.style.opacity = 0, 1200);
            }
        }
    });
}

/**
 * 更新违规选择框的颜色
 */
function updateStatusColor(el) {
    el.className = 'status-select ' + (el.value === '是' ? 'text-red' : 'text-green');
    saveData(el);
}

/**
 * 自动填充组织架构
 */
let debounceTimer;
function fetchOrg(el) {
    const val = el.value.trim();
    const form = el.closest('.live-form');
    if (val.length < 2) return;

    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
        fetch(`/api/query_org?unit=${encodeURIComponent(val)}`)
            .then(res => res.json())
            .then(res => {
                if (res.status === 'success') {
                    if (res.data) {
                        // 查到了对应信息，自动填充
                        form.querySelector('[name="biz_domain"]').value = res.data.biz_domain;
                        form.querySelector('[name="it_dept"]').value = res.data.it_dept;
                    } else {
                        // 查不到信息时，强制标记为异常
                        form.querySelector('[name="biz_domain"]').value = '异常';
                        form.querySelector('[name="it_dept"]').value = '异常';
                    }
                    saveData(el); // 填充后自动触发保存并广播给所有人
                }
            });
    }, 600);
}

/**
 * 操作接口：新建、置顶、删除
 */
function createNew() {
    fetch('/api/events', { method: 'POST', headers: API_HEADERS });
}

function topItem(id) {
    fetch(`/api/events/${id}/top`, { method: 'POST', headers: API_HEADERS });
}

function deleteItem(id) {
    if (confirm('⚠️ 确定要彻底删除该档案吗？此操作无法撤销。')) {
        fetch(`/api/events/${id}`, { method: 'DELETE', headers: API_HEADERS });
    }
}

/**
 * 一键复制内容
 */
function copyLiveCard(btn) {
    const card = btn.closest('.threat-card');
    const form = card.querySelector('.live-form');
    const getVal = (name) => form.querySelector(`[name="${name}"]`).value.trim();

    const textToCopy = 
        "1、威胁事件风险分析：" + getVal('risk_analysis') + "\n" +
        "2、威胁事件根因分析：" + getVal('root_cause') + "\n" +
        "3、威胁事件处置措施：" + getVal('disposal') + "\n" +
        "4、威胁事件优化建议：" + getVal('advice') + "\n" +
        "5、是否违规：" + getVal('is_violation') + "\n" +
        "6、责任单位：" + getVal('resp_unit') + "\n" +
        "7、业务领域：" + getVal('biz_domain') + "\n" +
        "8、IT归口：" + getVal('it_dept') + "\n" +
        "9、事件责任人：" + getVal('handler') + "\n" +
        "10、备注：" + getVal('remark');

    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(textToCopy).then(() => showCopyFeedback(btn));
    } else {
        const textArea = document.createElement("textarea");
        textArea.value = textToCopy;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        textArea.style.top = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            showCopyFeedback(btn);
        } catch (err) {
            alert('复制失败，请手动选择文字');
        }
        document.body.removeChild(textArea);
    }
}

function showCopyFeedback(btn) {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check-lg"></i> 已复制';
    btn.style.color = '#198754';
    setTimeout(() => {
        btn.innerHTML = originalHtml;
        btn.style.color = '';
    }, 1500);
}