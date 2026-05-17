const connTable = document.getElementById('conn-table');
const searchInput = document.getElementById('search');
const exitBtn = document.getElementById('exit-btn');
const restartBtn = document.getElementById('restart-btn');
const statusDiv = document.getElementById('status');
const tableContainer = document.querySelector('.table-container');

let connections = [];

function connect() {
    const ws = new WebSocket(`ws://${location.host}/ws`);

    ws.onopen = () => {
        statusDiv.textContent = 'Подключено. Мониторинг активен.';
    };

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
    const filtered = connections.filter(c =>
        c.proc.toLowerCase().includes(filter) ||
        c.pid.toString().includes(filter) ||
        c.local.includes(filter) ||
        c.remote.includes(filter)
    );

    connTable.innerHTML = filtered.map(c => `
        <tr>
            <td><span style="color: ${c.proto === 'TCP' ? '#58a6ff' : '#d29922'}">${c.proto}</span></td>
            <td><strong>${c.proc}</strong></td>
            <td><code>${c.pid}</code></td>
            <td>${c.local}</td>
            <td>${c.remote}</td>
            <td style="color: ${c.state === 'ESTAB' ? '#3fb950' : '#8b949e'}">${c.state}</td>
        </tr>
    `).join('');
}

searchInput.addEventListener('input', render);

// Global Prevention to avoid browser navigation on dropped files
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

// Drag and Drop Handling
tableContainer.addEventListener('dragover', (e) => {
    e.preventDefault();
    tableContainer.classList.add('drag-over');
});

tableContainer.addEventListener('dragleave', () => {
    tableContainer.classList.remove('drag-over');
});

tableContainer.addEventListener('drop', async (e) => {
    e.preventDefault();
    tableContainer.classList.remove('drag-over');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        const file = files[0];
        const formData = new FormData();
        formData.append('file', file);

        statusDiv.textContent = `Распознавание ${file.name}...`;

        try {
            const url = '/recognize';
            console.log(`Sending recognition request to ${url} for ${file.name}`);
            const response = await fetch(url, {
                method: 'POST',
                body: formData
            });
            console.log(`Response status: ${response.status}`);

            if (response.ok) {
                const data = await response.json();
                searchInput.value = data.proc;
                render();
                statusDiv.innerHTML = `Фильтр: <strong style="color:var(--accent-color)">${data.proc}</strong>`;
            } else {
                const errorText = await response.text();
                statusDiv.innerHTML = `<span style="color:var(--danger-color)">Ошибка: ${errorText || 'Не удалось распознать файл'}</span>`;
            }
        } catch (err) {
            console.error('Recognition error:', err);
            statusDiv.innerHTML = `<span style="color:var(--danger-color)">Ошибка: Соединение прервано (${err.message}). Проверьте консоль бэкенда.</span>`;
        }
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

connect();
