const proxyUrl = document.getElementById('proxy-url');
const device = document.getElementById('device');
const proxyState = document.getElementById('proxy-state');
const appsGrid = document.getElementById('apps-grid');
const logOutput = document.getElementById('log-output');
const catalogModal = document.getElementById('catalog-modal');
const catalogList = document.getElementById('catalog-list');
let config = { proxyUrl: '', device: '', processes: [], applications: [] };
let selectedIndex = -1;

function normalize(value) {
    return {
        proxyUrl: value?.proxyUrl || '',
        device: value?.device || '',
        processes: Array.isArray(value?.processes) ? value.processes : [],
        applications: Array.isArray(value?.applications) ? value.applications : []
    };
}
async function save() {
    config.proxyUrl = proxyUrl.value.trim();
    config.device = device.value.trim();
    const res = await fetch('/proxy-config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(config)
    });
    config = normalize(await res.json());
}
async function load() {
    config = normalize(await (await fetch('/proxy-config')).json());
    proxyUrl.value = config.proxyUrl;
    device.value = config.device;
    renderApps();
}
function renderApps() {
    appsGrid.innerHTML = config.applications.map((app, i) => `
        <div class="app-tile ${i === selectedIndex ? 'selected' : ''}" data-index="${i}">
            <div class="icon">${(app.name || app.processName || '?').slice(0, 1).toUpperCase()}</div>
            <div class="label" title="${app.path || app.processName}">${app.name || app.processName}</div>
        </div>`).join('');
}
async function refreshLog() {
    const res = await fetch('/log-tail');
    logOutput.textContent = res.status === 204 ? '' : await res.text();
    logOutput.scrollTop = logOutput.scrollHeight;
}
document.getElementById('test-btn').onclick = async () => {
    await save();
    const res = await fetch('/proxy-test', { method: 'POST' });
    proxyState.textContent = res.ok ? 'Прокси проверен' : 'Прокси недоступен';
    proxyState.className = `state ${res.ok ? 'ok' : 'bad'}`;
    refreshLog();
};
document.getElementById('choose-btn').onclick = async () => {
    const res = await fetch('/applications/choose-exe', { method: 'POST' });
    if (!res.ok) return;
    config = normalize(await res.json());
    renderApps();
    refreshLog();
};
document.getElementById('catalog-btn').onclick = async () => {
    const catalog = await (await fetch('/applications/catalog')).json();
    catalogList.innerHTML = catalog.map((app, index) =>
        `<div class="catalog-item" data-index="${index}"><strong>${app.name}</strong><br><small>${app.path}</small></div>`
    ).join('');
    catalogList._items = catalog;
    catalogModal.classList.remove('hidden');
};
document.getElementById('close-catalog').onclick = () => catalogModal.classList.add('hidden');
catalogList.onclick = async (e) => {
    const item = e.target.closest('.catalog-item');
    if (!item) return;
    const app = catalogList._items[Number(item.dataset.index)];
    const res = await fetch('/applications', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    renderApps();
    catalogModal.classList.add('hidden');
};
document.getElementById('delete-btn').onclick = async () => {
    if (selectedIndex < 0) return;
    const app = config.applications[selectedIndex];
    const res = await fetch('/applications', {
        method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedIndex = -1;
    renderApps();
};
document.getElementById('start-btn').onclick = async () => {
    await save();
    const res = await fetch('/proxy-engine/start', { method: 'POST' });
    proxyState.textContent = res.ok ? 'Прокси запущен' : `Ошибка запуска`;
    proxyState.className = `state ${res.ok ? 'ok' : 'bad'}`;
    refreshLog();
};
appsGrid.onclick = (e) => {
    const tile = e.target.closest('.app-tile');
    if (!tile) return;
    selectedIndex = Number(tile.dataset.index);
    renderApps();
};
appsGrid.ondblclick = async (e) => {
    const tile = e.target.closest('.app-tile');
    if (!tile) return;
    selectedIndex = Number(tile.dataset.index);
    await save();
    await fetch('/proxy-engine/start', { method: 'POST' });
    await fetch('/applications/launch', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config.applications[selectedIndex])
    });
    refreshLog();
};
proxyUrl.oninput = device.oninput = () => { proxyState.textContent = 'Прокси не проверен'; proxyState.className = 'state'; };
load();
refreshLog();
setInterval(refreshLog, 3000);
