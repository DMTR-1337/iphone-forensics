'use strict';

const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
const size = n =>
{
    let i = 0;
    for (n = Number(n); n >= 1024 && i < 4; i++) n /= 1024;
    return n.toFixed(i ? 1 : 0) + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i];
};

/* Translations. Keys shared by static [data-i18n] nodes and dynamic strings via t() */
const T = {
    en: {
        lang: 'FI', nav1: 'Prepare', nav2: 'Source', nav3: 'Workspace', nav4: 'Inventory', nav5: 'Deleted', nav6: 'Export', log: 'Log',
        s1h: 'Prepare', s1p: 'Two sources are supported. Both read only; nothing is sent to iCloud or the internet.',
        s1a: 'A. Connect the iPhone', s1a1: 'Install Apple Devices (Microsoft Store) or iTunes for the USB driver and the Apple Mobile Device Service.',
        s1a2: 'Connect by cable, unlock the iPhone, and tap Trust. The passcode is entered on the iPhone only, never here.',
        s1a3: 'Close the Photos app while reading so the photo database does not change mid-copy.',
        s1b: 'B. Use a local, unencrypted backup', s1b1: 'Preserve existing backups: archive them in Apple Devices / Finder, or copy the whole folder unchanged. A newer backup can overwrite an older one.',
        s1b2: 'An encrypted backup cannot be inspected. Turning encryption off removes passwords, Wi-Fi and Health data from future backups.',
        s1b3: 'With iCloud Photos on, the library is not in computer backups, so few photos may be found.',
        s1b4: 'macOS protects the backup folder: grant Full Disk Access to the terminal running this tool.', cont: 'Continue',
        s2h: 'Select a source', s2c: 'Connected iPhone', s2ch: 'Connect and unlock the iPhone; it appears here on its own. Read directly over USB, no backup needed.',
        s2b: 'Existing backup', s2ph: 'Custom backup folder, or a folder of backups', scan: 'Scan',
        s2enc: 'Encrypted backups were found. Their databases are not inspected, and backup passwords are never requested.',
        s3h: 'Audit workspace', s3l: 'Workspace location', s3go: 'Start analysis',
        s3hint: 'A timestamped folder with working/, exports/ and reports/ is created here. Keep it out of OneDrive, iCloud Drive, Dropbox and Google Drive.',
        s3int: 'Source integrity (SHA-256)', s4h: 'Inventory', s4cat: 'By category', s4dom: 'By domain', s4fol: 'By folder', s4csv: 'Full list: reports/inventory.csv',
        s5h: 'Recently Deleted', s5dist: 'Trash-state distribution', s5rng: 'Valid timestamp ranges', s5rec: 'Records marked Recently Deleted', s5f: 'Filter rows',
        s6h: 'Export & report', s6exp: 'Export media and thumbnails', s6or: 'Open reports', s6oe: 'Open exports',
        s6hint: 'Files are copied to exports/<domain>/<path> with original extensions. Unsafe names are renamed and logged in reports/renamed_paths.csv.',
        s6rem: 'Search for remnants', s6remh: "Searches the acquired data, not the phone's free space: unused space in Photos.sqlite for names of records that no longer exist, and caches for complete JPEG/PNG/HEIC/MOV/MP4 streams. Deleted files cannot be read back: iOS destroys each file's encryption key on deletion.",
        s6go: 'Search for remnants', s6cav: 'Caveats',
        cav1: 'Thumbnails are low-resolution derivatives, not full-resolution originals.',
        cav2: 'A cached or thumbnail file without a matching original does not prove the original was deleted.',
        cav3: 'Only items that were in Recently Deleted when the data was read are listed. Permanently deleted photos cannot be recovered.',
        cav4: 'iCloud Photos, Optimize Storage and backup exclusions limit what exists locally.',
        scanning: 'Scanning…', noBackups: 'No backups found.', none: 'None.', noDevice: 'No iPhone connected.',
        thDevice: 'Device', thiOS: 'iOS', thLast: 'Last backup', thSnap: 'Snapshot', thEnc: 'Encrypted', thModel: 'Model',
        thName: 'Name', thCount: 'Count', thSize: 'Size', thFile: 'File', thBefore: 'Before copy', thWorking: 'Working copy', thAfter: 'After', thResult: 'Result',
        thState: 'ZTRASHEDSTATE', thRows: 'Rows', thDated: 'With ZTRASHEDDATE', thInterp: 'Interpretation', thField: 'Field', thOldest: 'Oldest (UTC)', thNewest: 'Newest (UTC)',
        bSelect: 'Select', bAudit: 'Audit this iPhone', yes: 'yes', no: 'no', unknown: 'unknown', pending: 'pending', verified: 'verified', copied: 'copied',
        mismatch: 'MISMATCH', changedDev: 'changed on device',
        cRecords: 'Records', cPresent: 'Files present', cMissing: 'Missing', cThumb: 'Thumbnails', cMedia: 'Media', cContainer: 'Containers', cBytes: 'Bytes present',
        cNeeded: 'Needed', cAvail: 'Available', cStatus: 'Status', noSpace: 'Not enough space', cDelNames: 'Deleted record names', expStatus: 'Export status', allMatch: 'All match states',
        kDevice: 'Device', kModel: 'Model', kiOS: 'iOS', kSource: 'Source', kPath: 'Path', srcLive: 'iPhone over USB (live, read-only)', srcBackup: 'Backup from ',
        notFound: '(not found)', cloudMsg: 'This folder is inside %s. Synced folders can upload copies of your photos. Choose a local, non-synced folder.',
        encMsg: 'This backup is encrypted and cannot be inspected.', rowsOf: '%a of %b rows', first500: ', first 500 shown; full list in reports/recently_deleted.csv',
        defCloud: 'The default workspace is inside %s; choose a local folder in step 3.',
        carveHint: 'Details in reports/deleted_traces.csv and reports/carved.csv; images in carved/. Carved files are labelled copy-of-existing or permanently-deleted-candidate.'
    },
    fi: {
        lang: 'EN', nav1: 'Valmistelu', nav2: 'Lähde', nav3: 'Työtila', nav4: 'Inventaario', nav5: 'Poistetut', nav6: 'Vienti', log: 'Loki',
        s1h: 'Valmistelu', s1p: 'Kaksi lähdettä tuetaan. Molemmat luetaan vain; mitään ei lähetetä iCloudiin tai verkkoon.',
        s1a: 'A. Kytke iPhone', s1a1: 'Asenna Apple Devices (Microsoft Store) tai iTunes USB-ajuria ja Apple Mobile Device Service -palvelua varten.',
        s1a2: 'Kytke kaapelilla, avaa iPhonen lukitus ja hyväksy Trust. Pääsykoodi syötetään vain iPhonelle, ei koskaan tähän.',
        s1a3: 'Sulje Kuvat-sovellus lukemisen ajaksi, jottei kuvatietokanta muutu kesken kopioinnin.',
        s1b: 'B. Käytä salaamatonta paikallista backupia', s1b1: 'Säilytä vanhat backupit: arkistoi ne Apple Devicesissa / Finderissa tai kopioi koko kansio muuttumattomana. Uusi backup voi korvata vanhan.',
        s1b2: 'Salattua backupia ei voi tutkia. Salauksen poisto poistaa salasanat, Wi-Fin ja terveystiedot tulevista backupeista.',
        s1b3: 'Kun iCloud-kuvat on päällä, kirjasto ei ole konebackupissa, joten kuvia voi löytyä vähän.',
        s1b4: 'macOS suojaa backup-kansion: anna työkalun terminaalille Full Disk Access.', cont: 'Jatka',
        s2h: 'Valitse lähde', s2c: 'Kytketty iPhone', s2ch: 'Kytke ja avaa iPhonen lukitus; se ilmestyy tähän itsestään. Luetaan suoraan USB:n yli, backupia ei tarvita.',
        s2b: 'Olemassa oleva backup', s2ph: 'Oma backup-kansio tai kansio jossa on backupeja', scan: 'Etsi',
        s2enc: 'Salattuja backupeja löytyi. Niiden tietokantoja ei tutkita, eikä backup-salasanoja koskaan kysytä.',
        s3h: 'Tutkintatyötila', s3l: 'Työtilan sijainti', s3go: 'Aloita analyysi',
        s3hint: 'Tänne luodaan aikaleimattu kansio, jossa on working/, exports/ ja reports/. Pidä se poissa OneDrivesta, iCloud Drivesta, Dropboxista ja Google Drivesta.',
        s3int: 'Lähteen eheys (SHA-256)', s4h: 'Inventaario', s4cat: 'Luokittain', s4dom: 'Domaineittain', s4fol: 'Kansioittain', s4csv: 'Koko lista: reports/inventory.csv',
        s5h: 'Äskettäin poistetut', s5dist: 'Poistotilan jakauma', s5rng: 'Kelvolliset aikaleima-alueet', s5rec: 'Äskettäin poistetuiksi merkityt tietueet', s5f: 'Suodata rivejä',
        s6h: 'Vienti ja raportti', s6exp: 'Vie media ja pikkukuvat', s6or: 'Avaa raportit', s6oe: 'Avaa viennit',
        s6hint: 'Tiedostot kopioidaan polkuun exports/<domain>/<polku> alkuperäisin päättein. Vaaralliset nimet uudelleennimetään ja kirjataan tiedostoon reports/renamed_paths.csv.',
        s6rem: 'Etsi jäänteitä', s6remh: 'Etsii saadusta datasta, ei puhelimen vapaasta tilasta: Photos.sqliten käyttämättömästä tilasta nimiä tietueille joita ei enää ole, ja välimuisteista kokonaisia JPEG/PNG/HEIC/MOV/MP4-virtoja. Poistettuja tiedostoja ei voi lukea takaisin: iOS tuhoaa tiedoston salausavaimen poiston yhteydessä.',
        s6go: 'Etsi jäänteitä', s6cav: 'Varaumat',
        cav1: 'Pikkukuvat ovat matalaresoluutioisia johdannaisia, eivät täysikokoisia alkuperäisiä.',
        cav2: 'Välimuisti- tai pikkukuvatiedosto ilman alkuperäistä ei todista, että alkuperäinen on poistettu.',
        cav3: 'Vain datan lukuhetkellä Äskettäin poistetuissa olleet kohteet listataan. Lopullisesti poistettuja kuvia ei voi palauttaa.',
        cav4: 'iCloud-kuvat, Optimoi tallennustila ja backup-poissulut rajaavat paikallista sisältöä.',
        scanning: 'Etsitään…', noBackups: 'Backupeja ei löytynyt.', none: 'Ei mitään.', noDevice: 'Ei kytkettyä iPhonea.',
        thDevice: 'Laite', thiOS: 'iOS', thLast: 'Viimeisin backup', thSnap: 'Tila', thEnc: 'Salattu', thModel: 'Malli',
        thName: 'Nimi', thCount: 'Määrä', thSize: 'Koko', thFile: 'Tiedosto', thBefore: 'Ennen kopiota', thWorking: 'Työkopio', thAfter: 'Jälkeen', thResult: 'Tulos',
        thState: 'ZTRASHEDSTATE', thRows: 'Rivejä', thDated: 'ZTRASHEDDATE', thInterp: 'Tulkinta', thField: 'Kenttä', thOldest: 'Vanhin (UTC)', thNewest: 'Uusin (UTC)',
        bSelect: 'Valitse', bAudit: 'Tutki tämä iPhone', yes: 'kyllä', no: 'ei', unknown: 'tuntematon', pending: 'kesken', verified: 'varmistettu', copied: 'kopioitu',
        mismatch: 'EI TÄSMÄÄ', changedDev: 'muuttui laitteella',
        cRecords: 'Tietueita', cPresent: 'Tiedostoja tallessa', cMissing: 'Puuttuu', cThumb: 'Pikkukuvia', cMedia: 'Mediaa', cContainer: 'Säilöjä', cBytes: 'Tavuja tallessa',
        cNeeded: 'Tarvitaan', cAvail: 'Vapaana', cStatus: 'Tila', noSpace: 'Tila ei riitä', cDelNames: 'Poistettujen tietueiden nimiä', expStatus: 'Viennin tila', allMatch: 'Kaikki osumatilat',
        kDevice: 'Laite', kModel: 'Malli', kiOS: 'iOS', kSource: 'Lähde', kPath: 'Polku', srcLive: 'iPhone USB:n yli (live, vain luku)', srcBackup: 'Backup ajalta ',
        notFound: '(ei löydy)', cloudMsg: 'Tämä kansio on %s:n sisällä. Synkatut kansiot voivat ladata kuvistasi kopioita. Valitse paikallinen, synkkaamaton kansio.',
        encMsg: 'Tämä backup on salattu eikä sitä voi tutkia.', rowsOf: '%a / %b riviä', first500: ', 500 ensimmäistä näytetään; koko lista tiedostossa reports/recently_deleted.csv',
        defCloud: 'Oletustyötila on %s:n sisällä; valitse paikallinen kansio vaiheessa 3.',
        carveHint: 'Tarkemmin tiedostoissa reports/deleted_traces.csv ja reports/carved.csv; kuvat kansiossa carved/. Leikatut tiedostot on merkitty copy-of-existing tai permanently-deleted-candidate.'
    }
};

let lang = localStorage.getItem('lang') || 'fi';
const t = (k, a, b) => (T[lang][k] ?? T.en[k] ?? k).replace('%s', a).replace('%a', a).replace('%b', b);
const table = (head, rows) => rows.length
    ? `<table><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr>${rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</table>`
    : `<p class="hint">${t('none')}</p>`;
const breakdown = b => table([t('thName'), t('thCount'), t('thSize')], b.map(x => [x.name, x.count, size(x.bytes)]));
const card = (label, value) => `<div class="card"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;
const count = (b, name) => (b.find(x => x.name === name) || { count: 0 }).count;

let backups = [], found = [], selected = null, result = null, version = -1, running = false;

/* Every API call carries X-Audit, the server rejects requests without it */
async function api(path, params = {})
{
    const r = await fetch(path + '?' + new URLSearchParams(params), { headers: { 'X-Audit': '1' } });
    return r.json();
}

function applyI18n()
{
    document.documentElement.lang = lang;
    $('#lang').textContent = t('lang');
    document.querySelectorAll('[data-i18n]').forEach(e => e.textContent = t(e.dataset.i18n));
    document.querySelectorAll('[data-i18n-ph]').forEach(e => e.placeholder = t(e.dataset.i18nPh));
    renderBackups();
    renderDevices();
    if (selected) pick(selected, true);
    if (result) render(result);
}

function show(n)
{
    document.querySelectorAll('main > section').forEach(s => s.hidden = s.id !== 'step' + n);
    document.querySelectorAll('#steps button').forEach(b =>
    {
        b.classList.toggle('active', b.dataset.step == n);
        b.classList.toggle('done', !b.disabled && +b.dataset.step < n);
    });
}

function fail(msg)
{
    $('#error').hidden = !msg;
    $('#error').textContent = msg || '';
}

function renderBackups()
{
    $('#encrypted').hidden = !backups.some(b => b.encrypted);
    $('#backups').innerHTML = backups.length
        ? `<table><tr><th>${t('thDevice')}</th><th>${t('thiOS')}</th><th>${t('thLast')}</th><th>${t('thSnap')}</th><th>${t('thEnc')}</th><th></th></tr>${backups.map((b, i) => `<tr>
            <td>${esc(b.device || '—')}<br><small>${esc(b.path)}</small></td><td>${esc(b.ios)}</td><td>${esc(b.lastBackup)}</td>
            <td>${esc(b.snapshot || t('unknown'))}</td><td>${b.encrypted ? t('yes') : t('no')}</td>
            <td>${b.usable ? `<button class="ghost" data-pick="${i}">${t('bSelect')}</button>` : `<span class="bad">${esc(b.problem)}</span>`}</td></tr>`).join('')}</table>`
        : `<p class="hint">${t('noBackups')}</p>`;
}

async function scan(path)
{
    $('#backups').innerHTML = `<p class="hint">${t('scanning')}</p>`;
    const r = await api('/api/scan', { path });
    backups = r.backups;
    renderBackups();
    $('#backups').insertAdjacentHTML('afterbegin', r.errors.map(e => `<p class="alert">${esc(e)}</p>`).join(''));
}

function renderDevices()
{
    const html = found.length
        ? `<table><tr><th>${t('thDevice')}</th><th>${t('thModel')}</th><th>${t('thiOS')}</th><th></th></tr>${found.map((d, i) => `<tr><td>${esc(d.name || d.udid)}</td>
            <td>${esc(d.product)}</td><td>${esc(d.ios)}</td><td>${d.paired ? `<button class="primary" data-device="${i}">${t('bAudit')}</button>`
            : `<span class="bad">${esc(d.problem)}</span>`}</td></tr>`).join('')}</table>`
        : `<p class="hint">${t('noDevice')}</p>`;
    $('#devices').innerHTML = html;
}

/* Polls connected iPhones while the source step is visible */
async function devices()
{
    if (!$('#step2').hidden)
    {
        const r = await api('/api/devices');
        found = r.devices;
        const sig = r.error + JSON.stringify(found);
        if (sig !== $('#devices').dataset.sig)
        {
            $('#devices').dataset.sig = sig;
            renderDevices();
            if (r.error) $('#devices').insertAdjacentHTML('afterbegin', `<p class="alert">${esc(r.error)}</p>`);
        }
    }
    setTimeout(devices, 2500);
}

function pick(b, keep)
{
    selected = b;
    const src = b.live ? t('srcLive') : t('srcBackup') + b.lastBackup;
    $('#selected').innerHTML = [[t('kDevice'), b.device], [t('kModel'), b.product], [t('kiOS'), b.ios], [t('kSource'), src], [t('kPath'), b.path]]
        .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
    $('#start').disabled = running;
    if (!keep) show(3);
}

async function start()
{
    fail('');
    $('#cloud').hidden = true;
    const base = $('#base').value.trim();
    const r = await api('/api/start', selected.live ? { device: selected.udid, base } : { backup: selected.path, base });
    if (r.error && r.error.startsWith('cloud:'))
    {
        $('#cloud').hidden = false;
        $('#cloud').textContent = t('cloudMsg', r.error.slice(6));
    }
    else if (r.error === 'encrypted') fail(t('encMsg'));
    else if (r.error) fail(r.error);
    else poll();
}

async function poll()
{
    const s = await api('/api/status', { have: version });
    running = s.running;
    $('#progress').hidden = !s.phase;
    $('#progress i').style.width = (s.progress * 100).toFixed(1) + '%';
    $('#phase').textContent = s.phase + (running ? '…' : '');
    $('#log').textContent = s.log.join('\n');
    $('#start').disabled = running || !selected;
    fail(s.error);
    if (s.result)
    {
        version = s.version;
        render(s.result);
    }
    $('#export').disabled = running || !result || !result.export.analyzed || result.export.done || result.export.need > result.export.space;
    $('#carve').disabled = running || !result || !result.export.analyzed || result.carve.done;
    if (running) setTimeout(poll, 700);
}

function render(r)
{
    result = r;
    document.querySelectorAll('#steps button').forEach(b => b.disabled = false);

    const res = h => !h.after ? t('copied') : h.before === h.copy && h.before === h.after ? t('verified') : r.live ? t('changedDev') : t('mismatch');
    $('#hashes').innerHTML = table([t('thFile'), t('thBefore'), t('thWorking'), t('thAfter'), t('thResult')],
        r.hashes.map(h => [h.label, h.before, h.copy, h.after || t('pending'), res(h)]));

    const present = r.byExists.find(x => x.name === 'present') || { count: 0, bytes: 0 };
    $('#inv-cards').innerHTML = card(t('cRecords'), r.total) + card(t('cPresent'), present.count) + card(t('cMissing'), count(r.byExists, 'missing')) +
        card(t('cThumb'), count(r.byCategory, 'thumbnail')) + card(t('cMedia'), count(r.byCategory, 'media')) +
        card(t('cContainer'), count(r.byCategory, 'container')) + card(t('cBytes'), size(present.bytes));
    $('#by-category').innerHTML = breakdown(r.byCategory);
    $('#by-domain').innerHTML = breakdown(r.byDomain);
    $('#by-folder').innerHTML = breakdown(r.byFolder);

    const p = r.photos;
    $('#photo-status').textContent = p.status;
    $('#trash').innerHTML = table([t('thState'), t('thRows'), t('thDated'), t('thInterp')], p.trash.map(x => [x.value, x.count, x.dated, x.meaning]));
    $('#ranges').innerHTML = table([t('thField'), t('thOldest'), t('thNewest')], p.ranges);
    $('#match').innerHTML = `<option value="">${t('allMatch')}</option>` + p.byMatch.map(m => `<option>${esc(m.name)}</option>`).join('');
    deleted();

    const e = r.export;
    $('#space').innerHTML = card(t('cNeeded'), size(e.need)) + card(t('cAvail'), size(e.space)) + (e.need > e.space ? card(t('cStatus'), t('noSpace')) : '');
    $('#export-result').innerHTML = e.done ? `<h3>${t('expStatus')}</h3>` + breakdown(e.byStatus) : '';
    $('#carve-result').innerHTML = r.carve.done
        ? `<div class="cards">${card(t('cDelNames'), r.carve.traces)}</div>${breakdown(r.carve.byType)}<p class="hint">${t('carveHint')}</p>`
        : '';
}

function deleted()
{
    const p = result.photos, q = $('#filter').value.toLowerCase(), m = $('#match').value, mi = p.head.indexOf('matchStatus');
    const rows = p.rows.filter(r => (!m || r[mi] === m) && (!q || r.join(' ').toLowerCase().includes(q)));
    $('#deleted-count').textContent = t('rowsOf', rows.length, p.rows.length) + (rows.length > 500 ? t('first500') : '');
    $('#deleted').innerHTML = p.head.length ? table(p.head, rows.slice(0, 500)) : '';
}

document.addEventListener('click', e =>
{
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.step) show(b.dataset.step);
    if (b.dataset.pick) pick(backups[b.dataset.pick]);
    if (b.dataset.device)
    {
        const d = found[b.dataset.device];
        pick({ live: true, udid: d.udid, device: d.name, product: d.product, ios: d.ios, path: 'usb:' + d.udid });
    }
    if (b.dataset.open) api('/api/open', { what: b.dataset.open }).then(r => fail(r.error));
});

$('#lang').onclick = () =>
{
    lang = lang === 'fi' ? 'en' : 'fi';
    localStorage.setItem('lang', lang);
    applyI18n();
};
$('#scan-form').onsubmit = e =>
{
    e.preventDefault();
    scan($('#custom').value.trim());
};
$('#start').onclick = start;
$('#export').onclick = async () => { const r = await api('/api/export'); r.error ? fail(r.error) : poll(); };
$('#carve').onclick = async () => { const r = await api('/api/carve'); r.error ? fail(r.error) : poll(); };
$('#filter').oninput = $('#match').onchange = deleted;

(async () =>
{
    applyI18n();
    const env = await api('/api/env');
    document.body.dataset.os = env.os;
    $('#roots').innerHTML = env.roots.map(r => `<li><code>${esc(r.path)}</code>${r.exists ? '' : ' <em>' + t('notFound') + '</em>'}</li>`).join('');
    $('#base').value = env.workspaceBase;
    if (env.cloud) fail(t('defCloud', env.cloud));
    scan('');
    poll();
    devices();
})();
