document.addEventListener('DOMContentLoaded', () => {
    const form      = document.getElementById('check-form');
    const input     = document.getElementById('user-input');
    const button    = document.getElementById('submit-btn');
    const resultDiv = document.getElementById('result');

    // ── Tool status indicators ──────────────────────────────────────────────
    function toolBadge(name, status) {
        const icons = { pending: '⏳', running: '🔄', done: '✅', error: '❌', timeout: '⏱️' };
        const colors = { pending: '#a0a0a0', running: '#00f2ea', done: '#4ade80', error: '#ef4444', timeout: '#f59e0b' };
        const icon = icons[status] || '⏳';
        const color = colors[status] || '#a0a0a0';
        return `<span style="color:${color}; margin-right:1.2rem; font-size:0.9em;">${icon} <strong>${name}</strong>: ${status}</span>`;
    }

    function showRunning(h8Status, crStatus) {
        resultDiv.style.display = 'block';
        resultDiv.className = '';
        resultDiv.style.background = 'rgba(0,242,234,0.05)';
        resultDiv.style.border = '1px solid rgba(0,242,234,0.2)';
        resultDiv.style.color = '#a0a0a0';
        resultDiv.innerHTML = `
            <h3 style="color:#00f2ea; margin-bottom:0.8rem;">🔎 Scanning in Progress...</h3>
            <div style="margin-bottom:0.5rem;">
                ${toolBadge('h8mail', h8Status)}
                ${toolBadge('Cr3dOv3r', crStatus)}
            </div>
            <p style="font-size:0.85em;">Both tools are running in the cloud simultaneously. This may take up to 60–90 seconds.</p>
            <div style="margin-top:0.8rem; height:4px; border-radius:2px; background:rgba(255,255,255,0.1); overflow:hidden;">
                <div id="progress-bar" style="height:100%; background:linear-gradient(to right,#00f2ea,#ff0050); animation: progress-anim 2s linear infinite; width:60%;"></div>
            </div>
        `;
    }

    function showError(msg) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'danger';
        resultDiv.style.background = '';
        resultDiv.style.border = '';
        resultDiv.style.color = '';
        resultDiv.innerHTML = `<h3>⚠️ Error</h3><p>${msg}</p>`;
    }

    function showResults(data, email) {
        resultDiv.style.background = '';
        resultDiv.style.border = '';
        resultDiv.style.color = '';

        if (data.leaked) {
            resultDiv.className = 'danger';
            const rows = data.findings.map(f =>
                `<li style="margin:0.4rem 0; font-size:0.88em; line-height:1.5; word-break:break-all;">${f}</li>`
            ).join('');
            resultDiv.innerHTML = `
                <h3>⚠️ Data Breach Detected!</h3>
                <p style="margin:0.5rem 0 1rem;"><strong>${email}</strong> was found in <strong>${data.count}</strong> breach record(s).</p>
                <ul style="list-style:none; padding:0; border-top:1px solid rgba(255,0,0,0.2); padding-top:0.8rem;">
                    ${rows}
                </ul>
            `;
        } else {
            resultDiv.className = 'safe';
            resultDiv.innerHTML = `
                <h3>✅ No Breaches Found</h3>
                <p>Neither h8mail nor Cr3dOv3r found any leaked credentials for <strong>${email}</strong>.</p>
            `;
        }
    }

    // ── Polling loop ──────────────────────────────────────────────────────────
    function pollStatus(jobId, email, attempts) {
        if (attempts > 40) {
            // ~120 seconds max polling time
            showError('Scan timed out. The tools took too long to respond.');
            button.disabled = false;
            button.textContent = 'Check Status';
            return;
        }

        fetch(`/status/${jobId}`)
            .then(r => r.json())
            .then(data => {
                if (data.error) {
                    showError(data.error);
                    button.disabled = false;
                    button.textContent = 'Check Status';
                    return;
                }

                if (data.status === 'running') {
                    // Update live tool badges
                    showRunning(data.h8mail_status, data.cr3dover_status);
                    setTimeout(() => pollStatus(jobId, email, attempts + 1), 3000);
                } else if (data.status === 'complete') {
                    showResults(data, email);
                    button.disabled = false;
                    button.textContent = 'Check Status';
                }
            })
            .catch(() => {
                showError('Network error. Please try again.');
                button.disabled = false;
                button.textContent = 'Check Status';
            });
    }

    // ── Form Submit ───────────────────────────────────────────────────────────
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const value = input.value.trim();
        if (!value) return;

        button.disabled = true;
        button.innerHTML = 'Launching Scanners <div class="loading"></div>';
        showRunning('pending', 'pending');

        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: value })
            });
            const data = await response.json();

            if (data.error) {
                showError(data.error);
                button.disabled = false;
                button.textContent = 'Check Status';
                return;
            }

            // Start polling for results
            button.innerHTML = 'Scanning... <div class="loading"></div>';
            pollStatus(data.job_id, value, 0);

        } catch (err) {
            showError('Failed to connect to the server. Please try again.');
            button.disabled = false;
            button.textContent = 'Check Status';
        }
    });
});
