const device = document.getElementById('device');
const proxyState = document.getElementById('proxy-state');
const proxiesList = document.getElementById('proxies-list');
const proxyName = document.getElementById('proxy-name');
const proxyUrl = document.getElementById('proxy-url');
const appsGrid = document.getElementById('apps-grid');
const logOutput = document.getElementById('log-output');
const catalogModal = document.getElementById('catalog-modal');
const catalogList = document.getElementById('catalog-list');

let config = { device: '', proxies: [], applications: [] };
let selectedAppIndex = -1;
let selectedProxyId = '';
let draggedAppIndex = -1;

function normalize(value) {
    return {
        device: value?.device || '',
        proxies: Array.isArray(value?.proxies) ? value.proxies : [],
        applications: Array.isArray(value?.applications) ? value.applications : []
    };
}

function selectedProxy() {
    return config.proxies.find((proxy) => proxy.id === selectedProxyId) || config.proxies[0];
}

async function save() {
    config.device = device.value.trim();
    const res = await fetch('/proxy-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    });
    config = normalize(await res.json());
    if (!config.proxies.some((proxy) => proxy.id === selectedProxyId)) {
        selectedProxyId = config.proxies[0]?.id || '';
    }
    render();
}

async function load() {
    config = normalize(await (await fetch('/proxy-config')).json());
    device.value = config.device;
    selectedProxyId = config.proxies[0]?.id || '';
    render();
}

function render() {
    renderProxies();
    renderApps();
}

function renderProxies() {
    proxiesList.innerHTML = config.proxies.map((proxy) => `
        <button class="proxy-chip ${proxy.id === selectedProxyId ? 'selected' : ''}" data-id="${proxy.id}">
            <strong>${escapeHtml(proxy.name)}</strong>
            <span>${escapeHtml(maskProxy(proxy.url))}</span>
        </button>
    `).join('');
    const current = selectedProxy();
    proxyName.value = current?.name || '';
    proxyUrl.value = current?.url || '';
}

function renderApps() {
    appsGrid.innerHTML = config.applications.map((app, i) => {
        const proxy = config.proxies.find((item) => item.id === app.proxyId);
        return `
            <div class="app-tile ${i === selectedAppIndex ? 'selected' : ''}" data-index="${i}" draggable="true">
                <div class="icon">${escapeHtml((app.name || app.processName || '?').slice(0, 1).toUpperCase())}</div>
                <div class="label" title="${escapeHtml(app.path || app.processName)}">${escapeHtml(app.name || app.processName)}</div>
                <select class="app-proxy" data-index="${i}">
                    ${config.proxies.map((item) => `
                        <option value="${item.id}" ${item.id === app.proxyId ? 'selected' : ''}>${escapeHtml(item.name)}</option>
                    `).join('')}
                </select>
                <small>${escapeHtml(proxy?.name || 'Прокси не выбран')}</small>
            </div>`;
    }).join('');
}

function maskProxy(value) {
    if (!value) return 'не задан';
    try {
        const url = new URL(value.includes('://') ? value : `socks5://${value}`);
        return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ''}`;
    } catch {
        return value;
    }
}

function escapeHtml(value) {
    return String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
}

async function refreshLog() {
    const res = await fetch('/log-tail');
    logOutput.textContent = res.status === 204 ? '' : await res.text();
    logOutput.scrollTop = logOutput.scrollHeight;
}

document.getElementById('add-proxy-btn').onclick = async () => {
    const next = config.proxies.length + 1;
    const id = `proxy-${Date.now()}`;
    config.proxies.push({ id, name: `Прокси ${next}`, url: '' });
    selectedProxyId = id;
    renderProxies();
    proxyUrl.focus();
};

document.getElementById('save-proxy-btn').onclick = async () => {
    const current = selectedProxy();
    if (!current) return;
    current.name = proxyName.value.trim() || current.name;
    current.url = proxyUrl.value.trim();
    await save();
};

document.getElementById('delete-proxy-btn').onclick = async () => {
    if (config.proxies.length <= 1) return;
    const index = config.proxies.findIndex((proxy) => proxy.id === selectedProxyId);
    if (index < 0) return;
    const removed = config.proxies[index];
    config.proxies.splice(index, 1);
    selectedProxyId = config.proxies[Math.max(0, index - 1)]?.id || '';
    config.applications.forEach((app) => {
        if (app.proxyId === removed.id) app.proxyId = selectedProxyId;
    });
    await save();
};

proxiesList.onclick = (event) => {
    const chip = event.target.closest('.proxy-chip');
    if (!chip) return;
    selectedProxyId = chip.dataset.id;
    renderProxies();
};

document.getElementById('test-btn').onclick = async () => {
    await save();
    const res = await fetch('/proxy-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proxyId: selectedProxyId })
    });
    proxyState.textContent = res.ok ? 'Прокси проверен' : 'Прокси недоступен';
    proxyState.className = `state ${res.ok ? 'ok' : 'bad'}`;
    refreshLog();
};

document.getElementById('choose-btn').onclick = async () => {
    await save();
    const res = await fetch('/applications/choose-exe', { method: 'POST' });
    if (!res.ok) return;
    config = normalize(await res.json());
    render();
    refreshLog();
};

document.getElementById('catalog-btn').onclick = async () => {
    await save();
    const catalog = await (await fetch('/applications/catalog')).json();
    catalogList.innerHTML = catalog.map((app, index) =>
        `<div class="catalog-item" data-index="${index}"><strong>${escapeHtml(app.name)}</strong><br><small>${escapeHtml(app.path)}</small></div>`
    ).join('');
    catalogList._items = catalog;
    catalogModal.classList.remove('hidden');
};

document.getElementById('close-catalog').onclick = () => catalogModal.classList.add('hidden');

catalogList.onclick = async (event) => {
    const item = event.target.closest('.catalog-item');
    if (!item) return;
    const app = { ...catalogList._items[Number(item.dataset.index)], proxyId: selectedProxyId };
    const res = await fetch('/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    render();
    catalogModal.classList.add('hidden');
};

document.getElementById('delete-btn').onclick = async () => {
    if (selectedAppIndex < 0) return;
    const app = config.applications[selectedAppIndex];
    const res = await fetch('/applications', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedAppIndex = -1;
    renderApps();
};

document.getElementById('start-btn').onclick = async () => {
    await save();
    const res = await fetch('/proxy-engine/start', { method: 'POST' });
    proxyState.textContent = res.ok ? 'Маршрутизатор запущен' : 'Ошибка запуска';
    proxyState.className = `state ${res.ok ? 'ok' : 'bad'}`;
    refreshLog();
};

appsGrid.onclick = (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('select')) return;
    selectedAppIndex = Number(tile.dataset.index);
    renderApps();
};

appsGrid.onchange = async (event) => {
    const select = event.target.closest('.app-proxy');
    if (!select) return;
    config.applications[Number(select.dataset.index)].proxyId = select.value;
    await save();
};

appsGrid.ondblclick = async (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('select')) return;
    selectedAppIndex = Number(tile.dataset.index);
    await save();
    const res = await fetch('/applications/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config.applications[selectedAppIndex])
    });
    proxyState.textContent = res.ok ? 'Приложение запущено через прокси' : 'Ошибка запуска';
    proxyState.className = `state ${res.ok ? 'ok' : 'bad'}`;
    refreshLog();
};

appsGrid.ondragstart = (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile) return;
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

device.oninput = () => {
    proxyState.textContent = 'Настройки изменены';
    proxyState.className = 'state';
};

load();
refreshLog();
setInterval(refreshLog, 3000);
