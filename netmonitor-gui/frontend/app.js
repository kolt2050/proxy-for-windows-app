const connTable = document.getElementById('conn-table');
const searchInput = document.getElementById('search');
const exitBtn = document.getElementById('exit-btn');
const restartBtn = document.getElementById('restart-btn');
const saveProxyBtn = document.getElementById('save-proxy-btn');
const startProxyBtn = document.getElementById('start-proxy-btn');
const stopProxyBtn = document.getElementById('stop-proxy-btn');
const proxyUrlInput = document.getElementById('proxy-url');
const deviceInput = document.getElementById('device');
const selectedProcessesDiv = document.getElementById('selected-processes');
const statusDiv = document.getElementById('status');
const tableContainer = document.querySelector('.table-container');

let connections = [];
let proxyConfig = { proxyUrl: '', device: '', processes: [] };

function normalizedProcessSet() {
    return new Set(proxyConfig.processes.map(p => p.toLowerCase()));
}

async function loadProxyConfig() {
    const response = await fetch('/proxy-config');
    proxyConfig = await response.json();
    proxyUrlInput.value = proxyConfig.proxyUrl || '';
    deviceInput.value = proxyConfig.device || '';
    renderSelectedProcesses();
    render();
}

async function saveProxyConfig() {
    proxyConfig.proxyUrl = proxyUrlInput.value.trim();
    proxyConfig.device = deviceInput.value.trim();
    const response = await fetch('/proxy-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proxyConfig)
    });
    if (!response.ok) throw new Error(await response.text());
    proxyConfig = await response.json();
    proxyUrlInput.value = proxyConfig.proxyUrl || '';
    deviceInput.value = proxyConfig.device || '';
    renderSelectedProcesses();
    render();
}

function toggleProcess(processName) {
    if (!processName || processName.startsWith('Unknown') || processName === 'Access Denied') return;
    const key = processName.toLowerCase();
    const exists = proxyConfig.processes.some(p => p.toLowerCase() === key);
    proxyConfig.processes = exists
        ? proxyConfig.processes.filter(p => p.toLowerCase() !== key)
        : [...proxyConfig.processes, processName];
    renderSelectedProcesses();
    render();
}

function renderSelectedProcesses() {
    if (proxyConfig.processes.length === 0) {
        selectedProcessesDiv.innerHTML = '<span class="muted">не выбрано</span>';
        return;
    }
    selectedProcessesDiv.innerHTML = proxyConfig.processes.map(process => `
        <button class="chip" data-process="${process}" title="Убрать">${process} ×</button>
    `).join('');
}

function connect() {
    const ws = new WebSocket(`ws://${location.host}/ws`);
    ws.onopen = () => statusDiv.textContent = 'Подключено. Мониторинг активен.';
    ws.onmessage = (event) => {
        connections = JSON.parse(event.data);
        render();
    };
    ws.onclose = () => {
        statusDiv.textContent = 'Отключено. Повторное подключение...';
        setTimeout(connect, 2000);
    };
}

function render() {
    const filter = searchInput.value.toLowerCase();
    const selected = normalizedProcessSet();
    const filtered = connections.filter(c =>
        c.proc.toLowerCase().includes(filter) ||
        c.pid.toString().includes(filter) ||
        c.local.includes(filter) ||
        c.remote.includes(filter)
    );

    connTable.innerHTML = filtered.map(c => {
        const isSelected = selected.has(c.proc.toLowerCase());
        return `
            <tr data-process="${c.proc}" class="${isSelected ? 'selected-row' : ''}">
                <td>${isSelected ? '<span class="route proxy">proxy</span>' : '<span class="route direct">direct</span>'}</td>
                <td><span style="color: ${c.proto.startsWith('TCP') ? '#58a6ff' : '#d29922'}">${c.proto}</span></td>
                <td><strong>${c.proc}</strong></td>
                <td><code>${c.pid}</code></td>
                <td>${c.local}</td>
                <td>${c.remote}</td>
                <td style="color: ${c.state === 'ESTAB' ? '#3fb950' : '#8b949e'}">${c.state}</td>
            </tr>
        `;
    }).join('');
}

searchInput.addEventListener('input', render);
proxyUrlInput.addEventListener('input', () => proxyConfig.proxyUrl = proxyUrlInput.value);
deviceInput.addEventListener('input', () => proxyConfig.device = deviceInput.value);
saveProxyBtn.addEventListener('click', async () => {
    try {
        await saveProxyConfig();
        statusDiv.textContent = 'Настройки прокси сохранены.';
    } catch (err) {
        statusDiv.textContent = `Ошибка сохранения: ${err.message}`;
    }
});

startProxyBtn.addEventListener('click', async () => {
    try {
        await saveProxyConfig();
        const response = await fetch('/proxy-engine/start', { method: 'POST' });
        if (!response.ok) throw new Error(await response.text());
        statusDiv.textContent = 'Прокси-движок запущен.';
    } catch (err) {
        statusDiv.textContent = `Не удалось запустить прокси: ${err.message}`;
    }
});

stopProxyBtn.addEventListener('click', async () => {
    try {
        const response = await fetch('/proxy-engine/stop', { method: 'POST' });
        if (!response.ok) throw new Error(await response.text());
        statusDiv.textContent = 'Прокси-движок остановлен.';
    } catch (err) {
        statusDiv.textContent = `Не удалось остановить прокси: ${err.message}`;
    }
});

connTable.addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-process]');
    if (row) toggleProcess(row.dataset.process);
});

selectedProcessesDiv.addEventListener('click', (event) => {
    const chip = event.target.closest('.chip[data-process]');
    if (chip) toggleProcess(chip.dataset.process);
});

window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());
tableContainer.addEventListener('dragover', (e) => {
    e.preventDefault();
    tableContainer.classList.add('drag-over');
});
tableContainer.addEventListener('dragleave', () => tableContainer.classList.remove('drag-over'));
tableContainer.addEventListener('drop', async (e) => {
    e.preventDefault();
    tableContainer.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    const formData = new FormData();
    formData.append('file', file);
    statusDiv.textContent = `Распознавание ${file.name}...`;

    try {
        const response = await fetch('/recognize', { method: 'POST', body: formData });
        if (!response.ok) throw new Error(await response.text());
        const data = await response.json();
        toggleProcess(data.proc);
        statusDiv.innerHTML = `Выбран процесс: <strong>${data.proc}</strong>`;
    } catch (err) {
        statusDiv.textContent = `Ошибка распознавания: ${err.message}`;
    }
});

restartBtn.addEventListener('click', () => {
    if (confirm('Перезапустить NetMonitor?')) {
        restartBtn.disabled = true;
        exitBtn.disabled = true;
        statusDiv.textContent = 'Перезапуск...';
        fetch('/restart');
    }
});

exitBtn.addEventListener('click', () => {
    if (confirm('Выйти из NetMonitor?')) {
        restartBtn.disabled = true;
        exitBtn.disabled = true;
        fetch('/exit');
    }
});

loadProxyConfig().catch(err => {
    statusDiv.textContent = `Не удалось загрузить настройки прокси: ${err.message}`;
});
connect();
