const proxyState = document.getElementById('proxy-state');
const appsGrid = document.getElementById('apps-grid');
const logOutput = document.getElementById('log-output');
const logSource = document.getElementById('log-source');
const appVersion = document.getElementById('app-version');
const catalogModal = document.getElementById('catalog-modal');
const catalogList = document.getElementById('catalog-list');
const catalogSearch = document.getElementById('catalog-search');
const deleteModal = document.getElementById('delete-modal');
const deleteModalText = document.getElementById('delete-modal-text');
const clearCacheBtn = document.createElement('button');
clearCacheBtn.id = 'clear-cache-btn';
clearCacheBtn.textContent = '\u041e\u0447\u0438\u0441\u0442\u0438\u0442\u044c \u043a\u044d\u0448';
document.getElementById('choose-btn')?.after(clearCacheBtn);
let pendingDeleteIndex = -1;

let config = { applications: [] };
let selectedAppIndex = -1;
let draggedAppIndex = -1;
const proxyMetadata = new Map();
const proxyChecks = new Map();

function normalize(value) {
    return {
        applications: Array.isArray(value?.applications) ? value.applications : []
    };
}

async function save() {
    const res = await fetch('/proxy-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    });
    config = normalize(await res.json());
    renderApps();
    renderLogSources();
}

async function load() {
    await loadVersion();
    config = normalize(await (await fetch('/proxy-config')).json());
    renderApps();
    renderLogSources();
}

async function loadVersion() {
    try {
        const res = await fetch('/version');
        const payload = await res.json();
        if (payload?.version) appVersion.textContent = payload.version;
    } catch {
    }
}

function renderApps() {
    appsGrid.innerHTML = config.applications.map((app, i) => `
        <div class="app-tile ${tileClasses(app, i)}" data-index="${i}" draggable="true">
            <div class="icon has-image">
                <img src="/application-icon?path=${encodeURIComponent(app.path || '')}" alt="" onerror="this.remove(); this.parentElement.classList.remove('has-image'); this.parentElement.textContent='${escapeHtml((app.name || app.processName || '?').slice(0, 1).toUpperCase())}'">
            </div>
            <div class="label" title="${escapeHtml(app.path || app.processName)}">${escapeHtml(displayName(app, i))}</div>
            <div class="proxy-meta" title="${escapeHtml(app.proxy || '')}">${escapeHtml(proxySummary(app.proxy))}</div>
            <div class="proxy-check">${escapeHtml(proxyCheckLabel(app))}</div>
            <input
                class="app-proxy-input"
                data-index="${i}"
                type="password"
                value="${escapeHtml(app.proxy || '')}"
                placeholder="196.18.12.25:8000:login:password"
            >
        </div>
    `).join('');
    refreshProxyMetadata();
}

function renderLogSources() {
    const current = logSource.value || 'main';
    const options = [
        '<option value="main">Общий лог</option>',
        ...config.applications.map((app, index) => `<option value="${escapeHtml(app.id)}">${escapeHtml(displayName(app, index))}</option>`)
    ];
    logSource.innerHTML = options.join('');
    logSource.value = [...logSource.options].some((option) => option.value === current) ? current : 'main';
}

function baseName(app) {
    return app.name || app.processName || 'Приложение';
}

function displayName(app, index) {
    const name = baseName(app);
    const total = config.applications.filter((item) => baseName(item) === name).length;
    if (total <= 1) return name;
    const ordinal = config.applications
        .slice(0, index + 1)
        .filter((item) => baseName(item) === name)
        .length;
    return `${name} ${ordinal}`;
}

function tileClasses(app, index) {
    const classes = [];
    if (index === selectedAppIndex) classes.push('selected');
    if (!String(app.proxy || '').trim()) classes.push('missing-proxy');
    const check = proxyChecks.get(app.id);
    if (check === 'ok') classes.push('proxy-ok');
    if (check === 'bad') classes.push('proxy-bad');
    return classes.join(' ');
}

function proxyCheckLabel(app) {
    if (!String(app.proxy || '').trim()) return '\u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u0437\u0430\u0434\u0430\u043d';
    const check = proxyChecks.get(app.id);
    if (check === 'ok') return '\u041f\u0440\u043e\u043a\u0441\u0438 \u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d';
    if (check === 'bad') return '\u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d';
    if (check === 'checking') return '\u041f\u0440\u043e\u0432\u0435\u0440\u044f\u044e\u2026';
    return '\u041d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d';
}

function proxySummary(raw) {
    const value = String(raw || '').trim();
    if (!value) return '\u041f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u0437\u0430\u0434\u0430\u043d';
    const cached = proxyMetadata.get(value);
    if (cached?.country) return `${countryFlag(cached.countryCode)} ${cached.ip} \u00b7 ${cached.country}`.trim();
    if (cached?.ip) return cached.ip;
    return proxyIpFromRaw(value) || '\u041e\u043f\u0440\u0435\u0434\u0435\u043b\u044f\u044e \u043f\u0440\u043e\u043a\u0441\u0438\u2026';
}

function countryFlag(code) {
    const value = String(code || '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(value)) return '';
    return String.fromCodePoint(...[...value].map((char) => 127397 + char.charCodeAt(0)));
}

function proxyIpFromRaw(raw) {
    const parts = String(raw || '').trim().split(':');
    return parts.length >= 2 ? parts[0] : '';
}

async function refreshProxyMetadata() {
    const proxies = [...new Set(config.applications.map((app) => String(app.proxy || '').trim()).filter(Boolean))];
    await Promise.all(proxies.map(async (proxy) => {
        if (proxyMetadata.has(proxy)) return;
        proxyMetadata.set(proxy, { ip: proxyIpFromRaw(proxy) });
        try {
            const res = await fetch(`/proxy-metadata?proxy=${encodeURIComponent(proxy)}`);
            if (!res.ok) return;
            proxyMetadata.set(proxy, await res.json());
        } catch {
            // IP fallback is enough if the geo service is temporarily unavailable.
        }
    }));
    appsGrid.querySelectorAll('.app-tile').forEach((tile, index) => {
        const meta = tile.querySelector('.proxy-meta');
        if (meta) meta.textContent = proxySummary(config.applications[index]?.proxy);
    });
}

function escapeHtml(value) {
    return String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
}

function setState(text, kind = '') {
    proxyState.textContent = text;
    proxyState.className = `state ${kind}`.trim();
}

async function refreshLog() {
    const selected = logSource.value || 'main';
    const url = selected === 'main' ? '/log-tail' : `/shortcut-log?id=${encodeURIComponent(selected)}`;
    const res = await fetch(url);
    logOutput.textContent = res.status === 204 ? '' : await res.text();
    logOutput.scrollTop = logOutput.scrollHeight;
}

async function heartbeat() {
    try {
        await fetch('/ui-heartbeat', { method: 'POST', keepalive: true });
    } catch {
        // The backend may already be shutting down.
    }
}

document.getElementById('choose-btn').onclick = async () => {
    const button = document.getElementById('choose-btn');
    button.disabled = true;
    setState('Открываю выбор .exe…');
    try {
        const res = await fetch('/applications/choose-exe', { method: 'POST' });
        if (!res.ok) {
            const message = (await res.text()).trim();
            setState(message.includes('selection cancelled') ? 'Выбор .exe отменён' : 'Не удалось открыть выбор .exe', 'bad');
            refreshLog();
            return;
        }
        config = normalize(await res.json());
        selectedAppIndex = config.applications.length - 1;
        renderApps();
    renderLogSources();
        setState('Приложение добавлено', 'ok');
        refreshLog();
    } catch {
        setState('Не удалось открыть выбор .exe', 'bad');
    } finally {
        button.disabled = false;
    }
};

document.getElementById('export-btn').onclick = async () => {
    setState('\u042d\u043a\u0441\u043f\u043e\u0440\u0442\u0438\u0440\u0443\u044e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e\u2026');
    const res = await fetch('/backup/export', { method: 'POST' });
    setState(res.ok ? '\u042d\u043a\u0441\u043f\u043e\u0440\u0442 \u0437\u0430\u0432\u0435\u0440\u0448\u0451\u043d' : '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c', res.ok ? 'ok' : 'bad');
};

document.getElementById('import-btn').onclick = async () => {
    setState('\u0418\u043c\u043f\u043e\u0440\u0442\u0438\u0440\u0443\u044e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e\u2026');
    const res = await fetch('/backup/import', { method: 'POST' });
    if (!res.ok) {
        setState('\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0438\u043c\u043f\u043e\u0440\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c', 'bad');
        return;
    }
    config = normalize(await res.json());
    selectedAppIndex = -1;
    renderApps();
    renderLogSources();
    setState('\u0418\u043c\u043f\u043e\u0440\u0442 \u0437\u0430\u0432\u0435\u0440\u0448\u0451\u043d', 'ok');
};

document.getElementById('test-all-btn').onclick = async () => {
    const apps = config.applications;
    if (!apps.length) return;
    setState('\u041f\u0440\u043e\u0432\u0435\u0440\u044f\u044e \u043f\u0440\u043e\u043a\u0441\u0438\u2026');
    apps.forEach((app) => proxyChecks.set(app.id, app.proxy?.trim() ? 'checking' : 'bad'));
    renderApps();
    renderLogSources();
    await Promise.all(apps.map(async (app) => {
        if (!app.proxy?.trim()) return;
        try {
            const res = await fetch('/proxy-test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ proxy: app.proxy })
            });
            proxyChecks.set(app.id, res.ok ? 'ok' : 'bad');
        } catch {
            proxyChecks.set(app.id, 'bad');
        }
    }));
    renderApps();
    renderLogSources();
    const bad = apps.filter((app) => proxyChecks.get(app.id) !== 'ok').length;
    setState(bad ? `\u041f\u0440\u043e\u0431\u043b\u0435\u043c\u043d\u044b\u0445 \u044f\u0440\u043b\u044b\u043a\u043e\u0432: ${bad}` : '\u0412\u0441\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b', bad ? 'bad' : 'ok');
};

document.getElementById('catalog-btn').onclick = async () => {
    const catalog = await (await fetch('/applications/catalog')).json();
    catalogList._items = catalog;
    catalogSearch.value = '';
    renderCatalog(catalog);
    catalogModal.classList.remove('hidden');
    catalogSearch.focus();
};

document.getElementById('close-catalog').onclick = () => catalogModal.classList.add('hidden');

catalogList.onclick = async (event) => {
    const item = event.target.closest('.catalog-item');
    if (!item) return;
    const app = { ...catalogList._items[Number(item.dataset.index)], id: crypto.randomUUID(), proxy: '' };
    const res = await fetch('/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedAppIndex = config.applications.length - 1;
    renderApps();
    renderLogSources();
    catalogModal.classList.add('hidden');
};

function renderCatalog(items) {
    catalogList.innerHTML = items.map((app) => {
        const index = catalogList._items.indexOf(app);
        return `<div class="catalog-item" data-index="${index}"><strong>${escapeHtml(app.name)}</strong><br><small>${escapeHtml(app.path)}</small></div>`;
    }).join('');
}

catalogSearch.oninput = () => {
    const query = catalogSearch.value.trim().toLowerCase();
    const items = catalogList._items || [];
    const filtered = !query ? items : items.filter((app) =>
        `${app.name} ${app.path} ${app.processName}`.toLowerCase().includes(query)
    );
    renderCatalog(filtered);
};

document.getElementById('delete-btn').onclick = async () => {
    if (selectedAppIndex < 0) return;
    const app = config.applications[selectedAppIndex];
    pendingDeleteIndex = selectedAppIndex;
    deleteModalText.textContent = `Ярлык «${displayName(app, selectedAppIndex)}» будет удалён.`;
    deleteModal.classList.remove('hidden');
};

document.getElementById('cancel-delete').onclick = () => {
    pendingDeleteIndex = -1;
    deleteModal.classList.add('hidden');
};

document.getElementById('confirm-delete').onclick = async () => {
    if (pendingDeleteIndex < 0) return;
    const app = config.applications[pendingDeleteIndex];
    const res = await fetch('/applications', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedAppIndex = -1;
    pendingDeleteIndex = -1;
    deleteModal.classList.add('hidden');
    renderApps();
    renderLogSources();
};

clearCacheBtn.onclick = async () => {
    if (selectedAppIndex < 0) {
        setState('\u0421\u043d\u0430\u0447\u0430\u043b\u0430 \u0432\u044b\u0431\u0435\u0440\u0438 Chrome-\u044f\u0440\u043b\u044b\u043a', 'bad');
        return;
    }
    const app = config.applications[selectedAppIndex];
    clearCacheBtn.disabled = true;
    setState('\u041e\u0447\u0438\u0449\u0430\u044e \u043a\u044d\u0448 managed-\u043f\u0440\u043e\u0444\u0438\u043b\u044f\u2026');
    try {
        const res = await fetch('/applications/clear-cache', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(app)
        });
        if (!res.ok) {
            setState((await res.text()).trim() || '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0447\u0438\u0441\u0442\u0438\u0442\u044c \u043a\u044d\u0448', 'bad');
            refreshLog();
            return;
        }
        const payload = await res.json();
        setState(`\u041a\u044d\u0448 \u043e\u0447\u0438\u0449\u0435\u043d: ${payload.removed || 0}`, 'ok');
        refreshLog();
    } catch {
        setState('\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0447\u0438\u0441\u0442\u0438\u0442\u044c \u043a\u044d\u0448', 'bad');
    } finally {
        clearCacheBtn.disabled = false;
    }
};

logSource.onchange = refreshLog;

appsGrid.onclick = (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('input')) return;
    selectedAppIndex = Number(tile.dataset.index);
    updateSelectedTile();
};

appsGrid.oninput = (event) => {
    const input = event.target.closest('.app-proxy-input');
    if (!input) return;
    const app = config.applications[Number(input.dataset.index)];
    app.proxy = input.value.trim();
    proxyChecks.delete(app.id);
    const meta = input.closest('.app-tile')?.querySelector('.proxy-meta');
    if (meta) meta.textContent = proxySummary(input.value.trim());
    setState('Прокси изменён');
};

appsGrid.onchange = async (event) => {
    const input = event.target.closest('.app-proxy-input');
    if (!input) return;
    const app = config.applications[Number(input.dataset.index)];
    app.proxy = input.value.trim();
    proxyChecks.delete(app.id);
    await save();
    await refreshProxyMetadata();
    setState('Прокси сохранён', 'ok');
};

appsGrid.ondblclick = async (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('input')) return;
    selectedAppIndex = Number(tile.dataset.index);
    await save();
    const app = config.applications[selectedAppIndex];
    if (!app.proxy?.trim()) {
        setState('Сначала укажи прокси для приложения', 'bad');
        return;
    }
    const res = await fetch('/applications/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    setState(res.ok ? 'Приложение запущено через прокси' : 'Ошибка запуска', res.ok ? 'ok' : 'bad');
    refreshLog();
};

function updateSelectedTile() {
    appsGrid.querySelectorAll('.app-tile').forEach((tile, index) => {
        tile.classList.toggle('selected', index === selectedAppIndex);
    });
}

appsGrid.ondragstart = (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('input')) return;
    draggedAppIndex = Number(tile.dataset.index);
    event.dataTransfer.effectAllowed = 'move';
};

appsGrid.ondragover = (event) => {
    if (event.target.closest('.app-tile')) event.preventDefault();
};

appsGrid.ondrop = async (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || draggedAppIndex < 0) return;
    event.preventDefault();
    const targetIndex = Number(tile.dataset.index);
    if (targetIndex === draggedAppIndex) return;
    const [moved] = config.applications.splice(draggedAppIndex, 1);
    config.applications.splice(targetIndex, 0, moved);
    selectedAppIndex = targetIndex;
    draggedAppIndex = -1;
    await save();
};

load();
refreshLog();
heartbeat();
setInterval(refreshLog, 3000);
setInterval(heartbeat, 3000);
