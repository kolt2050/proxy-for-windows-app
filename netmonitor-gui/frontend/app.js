const proxyState = document.getElementById('proxy-state');
const appsGrid = document.getElementById('apps-grid');
const logOutput = document.getElementById('log-output');
const catalogModal = document.getElementById('catalog-modal');
const catalogList = document.getElementById('catalog-list');
const catalogSearch = document.getElementById('catalog-search');

let config = { applications: [] };
let selectedAppIndex = -1;
let draggedAppIndex = -1;

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
}

async function load() {
    config = normalize(await (await fetch('/proxy-config')).json());
    renderApps();
}

function renderApps() {
    appsGrid.innerHTML = config.applications.map((app, i) => `
        <div class="app-tile ${i === selectedAppIndex ? 'selected' : ''}" data-index="${i}" draggable="true">
            <div class="icon">${escapeHtml((app.name || app.processName || '?').slice(0, 1).toUpperCase())}</div>
            <div class="label" title="${escapeHtml(app.path || app.processName)}">${escapeHtml(app.name || app.processName)}</div>
            <input
                class="app-proxy-input"
                data-index="${i}"
                type="password"
                value="${escapeHtml(app.proxy || '')}"
                placeholder="196.18.12.25:8000:login:password"
            >
        </div>
    `).join('');
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
    const res = await fetch('/log-tail');
    logOutput.textContent = res.status === 204 ? '' : await res.text();
    logOutput.scrollTop = logOutput.scrollHeight;
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
        setState('Приложение добавлено', 'ok');
        refreshLog();
    } catch {
        setState('Не удалось открыть выбор .exe', 'bad');
    } finally {
        button.disabled = false;
    }
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
    const app = { ...catalogList._items[Number(item.dataset.index)], proxy: '' };
    const res = await fetch('/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedAppIndex = config.applications.length - 1;
    renderApps();
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
    const res = await fetch('/applications', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(app)
    });
    config = normalize(await res.json());
    selectedAppIndex = -1;
    renderApps();
};

appsGrid.onclick = (event) => {
    const tile = event.target.closest('.app-tile');
    if (!tile || event.target.matches('input')) return;
    selectedAppIndex = Number(tile.dataset.index);
    updateSelectedTile();
};

appsGrid.oninput = (event) => {
    const input = event.target.closest('.app-proxy-input');
    if (!input) return;
    config.applications[Number(input.dataset.index)].proxy = input.value.trim();
    setState('Прокси изменён');
};

appsGrid.onchange = async (event) => {
    const input = event.target.closest('.app-proxy-input');
    if (!input) return;
    config.applications[Number(input.dataset.index)].proxy = input.value.trim();
    await save();
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
setInterval(refreshLog, 3000);
