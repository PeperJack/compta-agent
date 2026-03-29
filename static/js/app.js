const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const fileList = document.getElementById('fileList');
const processBtn = document.getElementById('processBtn');

let selectedFiles = [];

// Drag & Drop
['dragenter', 'dragover'].forEach(e => {
    dropzone.addEventListener(e, ev => {
        ev.preventDefault();
        dropzone.classList.add('dragover');
    });
});

['dragleave', 'drop'].forEach(e => {
    dropzone.addEventListener(e, ev => {
        ev.preventDefault();
        dropzone.classList.remove('dragover');
    });
});

dropzone.addEventListener('drop', e => {
    const files = Array.from(e.dataTransfer.files).filter(f => f.name.toLowerCase().endsWith('.pdf'));
    addFiles(files);
});

fileInput.addEventListener('change', () => {
    addFiles(Array.from(fileInput.files));
    fileInput.value = '';
});

function addFiles(files) {
    files.forEach(f => {
        if (!selectedFiles.find(s => s.name === f.name)) {
            selectedFiles.push(f);
        }
    });
    renderFiles();
}

function removeFile(idx) {
    selectedFiles.splice(idx, 1);
    renderFiles();
}

function renderFiles() {
    fileList.innerHTML = selectedFiles.map((f, i) => `
        <div class="file-item">
            <span class="file-item-name">\u{1F4CE} ${f.name}</span>
            <div style="display:flex;align-items:center;gap:12px">
                <span class="file-item-size">${(f.size / 1024).toFixed(0)} Ko</span>
                <button class="file-remove" onclick="removeFile(${i})">\u00D7</button>
            </div>
        </div>
    `).join('');

    processBtn.disabled = selectedFiles.length === 0;
}

// Process
processBtn.addEventListener('click', async () => {
    if (selectedFiles.length === 0) return;

    document.getElementById('upload-section').style.display = 'none';
    document.getElementById('loading').classList.add('active');

    const formData = new FormData();
    selectedFiles.forEach(f => formData.append('files', f));

    try {
        const resp = await fetch('/api/process', {
            method: 'POST',
            headers: { 'X-CSRF-Token': CSRF_TOKEN },
            body: formData
        });

        if (resp.status === 401) {
            window.location.href = '/login';
            return;
        }

        const data = await resp.json();

        if (data.error) {
            alert('Erreur : ' + data.error);
            resetAll();
            return;
        }

        showResults(data);
    } catch (err) {
        alert('Erreur de connexion : ' + err.message);
        resetAll();
    }
});

function showResults(data) {
    document.getElementById('loading').classList.remove('active');
    document.getElementById('results').classList.add('active');

    const s = data.summary;

    document.getElementById('resultSummary').textContent =
        `${s.total} justificatif(s) traite(s) \u2014 ${s.exploites} exploitable(s), ${s.inexploites} inexploitable(s)`;

    // Stats
    document.getElementById('stats').innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total</div>
            <div class="stat-value">${s.total}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Exploites</div>
            <div class="stat-value green">${s.exploites}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Rejetes</div>
            <div class="stat-value ${s.inexploites > 0 ? 'orange' : ''}">${s.inexploites}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Equilibre</div>
            <div class="stat-value ${s.equilibre ? 'green' : 'red'}">${s.equilibre ? '\u2713' : '\u2717'}</div>
        </div>
    `;

    // Downloads
    const dl = data.output_files;
    let dlHtml = '';

    if (dl.excel) {
        dlHtml += downloadCard('\u{1F4CA}', 'excel', dl.excel.name, 'Import Sage \u2014 ecritures comptables');
    }
    if (dl.stamped_pdf) {
        dlHtml += downloadCard('\u{1F4D1}', 'pdf-s', dl.stamped_pdf.name, 'Tickets vises avec tampon S');
    }
    if (dl.inexploitable_pdf) {
        dlHtml += downloadCard('\u26A0\uFE0F', 'pdf-x', dl.inexploitable_pdf.name, 'Justificatifs a corriger');
    }

    document.getElementById('downloads').innerHTML = dlHtml;

    // Detail table
    const tbody = document.getElementById('detailBody');
    tbody.innerHTML = data.results_detail.map(r => {
        const libelle = r.status === 'exploitable'
            ? (r.ecritures && r.ecritures[0] ? r.ecritures[0].libelle : '-')
            : r.raison;
        return `<tr>
            <td>${r.filename}</td>
            <td><span class="badge ${r.status === 'exploitable' ? 'ok' : 'ko'}">${r.status === 'exploitable' ? 'OK' : 'Rejet'}</span></td>
            <td>${r.reference || '-'}</td>
            <td>${libelle || '-'}</td>
        </tr>`;
    }).join('');
}

function downloadCard(icon, type, filename, desc) {
    return `
        <div class="download-card">
            <div class="download-info">
                <div class="download-icon ${type}">${icon}</div>
                <div>
                    <div class="download-name">${filename}</div>
                    <div class="download-desc">${desc}</div>
                </div>
            </div>
            <a href="/api/download/${filename}" class="download-btn">Telecharger</a>
        </div>
    `;
}

function resetAll() {
    selectedFiles = [];
    fileList.innerHTML = '';
    processBtn.disabled = true;
    document.getElementById('upload-section').style.display = 'block';
    document.getElementById('results').classList.remove('active');
    document.getElementById('loading').classList.remove('active');
}