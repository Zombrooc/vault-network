const icons = {
  plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  arrow: '<svg viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></svg>',
  lock: '<svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
  unlock: '<svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 7-2.5"/></svg>',
  folder: '<svg viewBox="0 0 24 24"><path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h5l2 2h8A1.5 1.5 0 0 1 21 9.5v7A1.5 1.5 0 0 1 19.5 18h-15A1.5 1.5 0 0 1 3 16.5z"/></svg>',
  file: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>',
  upload: '<svg viewBox="0 0 24 24"><path d="M12 16V4M7 9l5-5 5 5M5 20h14"/></svg>',
  download: '<svg viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5M5 20h14"/></svg>',
  share: '<svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="m8.2 10.8 7.6-4.5M8.2 13.2l7.6 4.5"/></svg>',
  check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
  close: '<svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg>',
  search: '<svg viewBox="0 0 24 24"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 4 4"/></svg>',
  warning: '<svg viewBox="0 0 24 24"><path d="m12 4 9 16H3z"/><path d="M12 9v5M12 17h.01"/></svg>',
  settings: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.8 1.8 0 0 0 .3 2l.1.1-1.8 1.8-.1-.1a1.8 1.8 0 0 0-2-.3 1.8 1.8 0 0 0-1 1.6v.2h-2.6v-.2a1.8 1.8 0 0 0-1-1.6 1.8 1.8 0 0 0-2 .3l-.1.1-1.8-1.8.1-.1a1.8 1.8 0 0 0 .3-2 1.8 1.8 0 0 0-1.6-1H6v-2.6h.2a1.8 1.8 0 0 0 1.6-1 1.8 1.8 0 0 0-.3-2l-.1-.1 1.8-1.8.1.1a1.8 1.8 0 0 0 2 .3 1.8 1.8 0 0 0 1-1.6V5h2.6v.2a1.8 1.8 0 0 0 1 1.6 1.8 1.8 0 0 0 2-.3l.1-.1 1.8 1.8-.1.1a1.8 1.8 0 0 0-.3 2 1.8 1.8 0 0 0 1.6 1h.2V14h-.2a1.8 1.8 0 0 0-1.6 1Z"/></svg>',
  pause: '<svg viewBox="0 0 24 24"><path d="M9 5v14M15 5v14"/></svg>',
  play: '<svg viewBox="0 0 24 24"><path d="m8 5 11 7-11 7z"/></svg>',
};

const nativeRuntime = Boolean(window.__TAURI__?.core?.invoke);
const state = {
  view: 'home',
  containers: nativeRuntime ? [] : [
    { name: 'Meu container pessoal', path: 'Documentos · Imagens · Projetos', size: '3,2 GB', updated: 'Hoje, 09:42', status: 'Desbloqueado', color: 'green', files: 128 },
    { name: 'Trabalho & Clientes', path: 'Financeiro · Contratos', size: '12,8 GB', updated: 'Ontem, 18:20', status: 'Bloqueado', color: 'warm', files: 84 },
    { name: 'Arquivo pessoal', path: 'Fotos · Viagens', size: '8,4 GB', updated: '12 out, 2026', status: 'Bloqueado', color: 'green', files: 246 },
  ],
  currentContainer: 0,
  selectedContact: 'Marina Alves',
  settingsTab: 'Segurança',
  nativePath: null,
  nativeObjects: [],
  nativeFolders: [],
  nativeFolder: '',
  autoLock: true,
  invitations: [],
  activity: [],
};

const view = document.querySelector('#app-view');
const modalBackdrop = document.querySelector('#modal-backdrop');
const modal = document.querySelector('#modal');
const filePicker = document.querySelector('#file-picker');
const nativeInvoke = window.__TAURI__?.core?.invoke;
let autoLockTimer;

function icon(name) { return icons[name] || ''; }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character])); }
function formatBytes(bytes) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(0)} KB`; if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`; return `${(bytes / 1024 ** 3).toFixed(1)} GB`; }
function adoptNativeContainer(path, objects) { let index = state.containers.findIndex(container => container.nativePath === path || container.path === path); if (index < 0) { state.containers.push({ name: path.split(/[\\/]/).filter(Boolean).pop() || 'Container local', path, nativePath: path, size: formatBytes(objects.reduce((total, object) => total + object.plaintext_len, 0)), updated: 'Agora', status: 'Desbloqueado', color: 'green', files: objects.length }); index = state.containers.length - 1; } state.currentContainer = index; state.nativePath = path; state.nativeObjects = objects; state.nativeFolder = ''; state.containers[index].path = path; state.containers[index].nativePath = path; state.containers[index].files = objects.length; state.containers[index].status = 'Desbloqueado'; }
async function refreshNativeFolders() { state.nativeFolders = nativeInvoke && state.nativePath ? await nativeInvoke('list_folders') : []; }
function folderParent(path) { const slash = path.lastIndexOf('/'); return slash < 0 ? '' : path.slice(0, slash); }
function folderName(path) { const slash = path.lastIndexOf('/'); return slash < 0 ? path : path.slice(slash + 1); }
function scheduleAutoLock() { clearTimeout(autoLockTimer); if (!state.autoLock || state.containers[state.currentContainer]?.status !== 'Desbloqueado') return; autoLockTimer = setTimeout(async () => { if (nativeInvoke && state.nativePath) { try { await nativeInvoke('lock_container'); } catch (error) { toast(String(error), true); return; } } state.containers[state.currentContainer].status = 'Bloqueado'; state.nativeObjects = []; state.nativeFolders = []; state.nativeFolder = ''; toast('Container bloqueado por inatividade.'); render(); }, 15 * 60 * 1000); }
function pill(text, tone = 'neutral') { return `<span class="pill pill-${tone}">${text}</span>`; }
function containerIcon(color = 'green') { return `<span class="container-icon ${color === 'warm' ? 'warm' : ''}">${icon('folder')}</span>`; }
function header(title, description, action = '') { return `<div class="page-heading"><div><p class="eyebrow">Vault Network / ${escapeHtml(title)}</p><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></div>${action}</div>`; }

function homeView() {
  const active = state.containers[state.currentContainer];
  if (!active) return `${header('Visão geral', 'Nenhum container está aberto nesta sessão.', `<button class="button-primary" data-action="new-container">${icon('plus')} Novo container</button>`)}<div class="card empty-state protected">${icon('lock')}<strong>Comece por um container</strong><p>Crie um novo container ou desbloqueie um diretório existente.</p><button class="button-secondary" data-action="unlock-container">${icon('unlock')} Desbloquear existente</button></div>`;
  const unlocked = active.status === 'Desbloqueado';
  const activity = state.activity.length ? state.activity.map(item => `<div class="activity-row"><span class="activity-icon ${item.kind}">${icon(item.icon)}</span><div class="row-main"><strong>${escapeHtml(item.title)}</strong><span>${escapeHtml(item.detail)}</span></div><span class="activity-time">Agora</span></div>`).join('') : '<div class="empty-state">Nenhuma atividade nesta sessão.</div>';
  return `${header('Visão geral', 'Tudo protegido. Tudo sob seu controle.', `<button class="button-primary" data-action="new-container">${icon('plus')} Novo container</button>`)}
    <section class="dashboard-grid">
      <article class="card hero-card"><p class="eyebrow">Container ativo</p><h2>${escapeHtml(active.name)}</h2><p>Seu espaço privado está protegido e disponível apenas nesta sessão.</p><div class="hero-meta"><span class="pill pill-light"><i class="status-dot"></i> ${active.status}</span><span class="mini-meta">Atualizado ${escapeHtml(active.updated.toLowerCase())}</span></div><div class="hero-actions"><button class="button-primary" data-action="${unlocked ? 'open-container' : 'unlock-container'}">${unlocked ? 'Abrir container' : 'Desbloquear'} ${icon(unlocked ? 'arrow' : 'unlock')}</button>${unlocked ? `<button class="button-secondary" data-action="lock-container">${icon('lock')} Bloquear</button>` : ''}</div></article>
      <article class="card usage-card"><div class="card-head"><h3>Armazenamento local</h3><a href="#" data-action="show-settings">Gerenciar</a></div><div class="usage-number">24,4 <span>GB de 100 GB</span></div><div class="meter"><span></span></div><div class="usage-note"><b>24%</b> utilizado · 75,6 GB disponíveis</div></article>
    </section>
    <section class="section-grid"><article class="card section-card"><div class="card-head"><h3>Containers recentes</h3><a href="#" data-action="show-containers">Ver todos ${icon('arrow')}</a></div>${state.containers.slice(0, 3).map(c => `<div class="container-row">${containerIcon(c.color)}<div class="row-main"><strong>${escapeHtml(c.name)}</strong><span>${escapeHtml(c.path)}</span></div><div class="row-end"><span>${escapeHtml(c.size)}</span>${pill(c.status, c.status === 'Desbloqueado' ? 'green' : 'neutral')}</div></div>`).join('')}</article>
      <article class="card section-card"><div class="card-head"><h3>Atividade recente</h3><a href="#" data-action="show-transfers">Ver atividade ${icon('arrow')}</a></div>${activity}</article></section>`;
}

function containersView() {
  const list = state.containers.length ? state.containers.map((c, i) => `<div class="list-row" data-container-row><button class="container-link" data-action="open-container" data-container-index="${i}">${containerIcon(c.color)}<span class="row-main"><strong>${escapeHtml(c.name)}</strong><span>${escapeHtml(c.path)} · ${c.files} itens</span></span></button><div class="row-end"><span>${escapeHtml(c.size)}</span></div><div class="row-end">${pill(c.status, c.status === 'Desbloqueado' ? 'green' : 'neutral')}</div><button class="icon-button row-menu" aria-label="Opções">•••</button></div>`).join('') : '<div class="empty-state">Nenhum container nesta sessão.</div>';
  return `${header('Meus containers', 'Seus espaços criptografados, organizados em um só lugar.', `<button class="button-primary" data-action="new-container">${icon('plus')} Novo container</button>`)}
    <div class="page-section"><div class="toolbar"><div class="search-box">${icon('search')}<input type="search" placeholder="Pesquisar containers" data-filter="containers" /></div><div class="filter-tabs"><button class="filter-tab active">Todos</button><button class="filter-tab">Desbloqueados</button><button class="filter-tab">Bloqueados</button></div></div><div class="card list-card"><div class="list-header"><span>Container</span><span>Tamanho</span><span>Estado</span><span></span></div><div id="container-list">${list}</div></div></div>`;
}

function sharesView() {
  const rows = state.invitations.map(invitation => `<div class="list-row"><div class="container-link"><span class="contact-avatar">${escapeHtml(invitation.recipient.slice(0, 2).toUpperCase())}</span><span class="row-main"><strong>Convite HPKE</strong><span>${escapeHtml(invitation.objectName)} · Permissão: ${invitation.seed ? 'download + seed' : 'download'}</span></span></div><div class="row-end"><span>${escapeHtml(invitation.expires)}</span></div><div class="row-end">${pill('Gerado', 'green')}</div><button class="icon-button row-menu" aria-label="Opções">•••</button></div>`).join('');
  return `${header('Compartilhamentos', 'Convites e permissões da sua rede privada.', `<div class="inline-actions"><button class="button-secondary" data-action="open-invitation" ${nativeInvoke ? '' : 'disabled'}>Abrir convite</button><button class="button-primary" data-action="new-share">${icon('share')} Novo compartilhamento</button></div>`)}
    <div class="page-section"><div class="card list-card"><div class="share-summary"><p>${state.invitations.length ? `<strong>${state.invitations.length} convite(s) gerado(s) nesta sessão.</strong>` : 'Nenhum convite foi gerado nesta sessão.'} O histórico persistente de compartilhamentos será adicionado com o transporte.</p></div>${rows || '<div class="empty-state">Gere um convite a partir de um objeto importado.</div>'}</div></div>`;
}

function transfersView() {
  return `${header('Transferências', 'Downloads autorizados passam somente pelo relay privado do convite.', `<button class="button-secondary" data-action="show-settings">${icon('settings')} Limites de rede</button>`)}<div class="page-section"><div class="card empty-state protected">${icon('download')}<strong>Nenhuma transferência ativa</strong><p>Abra um convite validado em Compartilhamentos para iniciar um download.</p></div></div>`;
}

function settingsView() {
  const tabs = ['Segurança', 'Privacidade', 'Rede', 'Armazenamento', 'Atualizações'];
  return `${header('Configurações', 'Controle local, privacidade e comportamento da rede.')}
    <div class="settings-layout page-section"><div class="settings-menu">${tabs.map(t => `<button class="${state.settingsTab === t ? 'active' : ''}" data-settings-tab="${t}">${t}</button>`).join('')}</div><article class="card settings-panel">${settingsPanel(state.settingsTab)}</article></div>`;
}

function settingsPanel(tab) {
  const content = {
    Segurança: ['Proteção do container', 'Configure bloqueio automático, recovery key e sessão local.', [['Bloqueio automático', 'Bloquear após 15 minutos de inatividade', state.autoLock], ['Exigir senha ao retomar', 'Solicitar a senha sempre que o app voltar ao foco', true], ['Limpar dados da WebView ao sair', 'Cache e histórico local são removidos ao encerrar', true]]],
    Privacidade: ['Privacidade por padrão', 'O app mantém o conteúdo no dispositivo e minimiza os metadados compartilhados.', [['Modo privado', 'Usar relay e impedir conexões diretas com participantes', true], ['Telemetria opcional', 'Compartilhar apenas métricas anônimas de desempenho', false], ['Mostrar avisos de exportação', 'Lembrar quando um arquivo deixar a proteção do container', true]]],
    Rede: ['Rede e relay', 'Transferências usam relay privado e descoberta rendezvous configurados nos convites.', [['Relay privado', 'Endpoint informado no convite', false], ['Semeadura', 'Disponível enquanto o container estiver desbloqueado', false], ['Limitar upload', 'Limite será aplicado ao iniciar transferências', false]]],
    Armazenamento: ['Armazenamento local', 'Gerencie espaço, segmentos e arquivos órfãos dos seus containers.', [['Coleta automática', 'Recolher blocos sem referência em segundo plano', true], ['Avisar sobre pastas sincronizadas', 'Alertar antes de abrir containers em pastas do Dropbox ou OneDrive', true]]],
    Atualizações: ['Atualizações', 'As versões são verificadas por assinatura antes da instalação.', [['Verificar automaticamente', 'Buscar atualizações ao iniciar o app', true], ['Canal de atualização', 'Estável · versão 1.1.0', false]]],
  }[tab];
  const actions = tab === 'Segurança'
    ? `<button class="button-secondary" data-action="change-password" ${nativeInvoke ? '' : 'disabled'}>Trocar senha</button><button class="button-secondary" data-action="rotate-recovery" ${nativeInvoke ? '' : 'disabled'}>Regenerar recovery key</button><button class="button-secondary" data-action="rotate-cmk" ${nativeInvoke ? '' : 'disabled'}>Rotacionar CMK</button><button class="button-secondary" data-action="export-backup" ${nativeInvoke ? '' : 'disabled'}>Exportar backup do header</button><button class="button-secondary" data-action="restore-backup" ${nativeInvoke ? '' : 'disabled'}>Restaurar backup do header</button><button class="button-secondary" data-action="create-contact-card" ${nativeInvoke ? '' : 'disabled'}>Gerar cartão de contato</button>`
    : tab === 'Armazenamento' ? `<button class="button-secondary" data-action="compact-container" ${nativeInvoke ? '' : 'disabled'}>Compactar segmentos</button>` : '';
  return `<h3>${content[0]}</h3><p>${content[1]}</p>${content[2].map(([title, desc, on]) => `<div class="setting-row"><div><strong>${title}</strong><span>${desc}</span></div><button class="toggle ${on ? 'on' : ''}" data-toggle data-setting="${escapeHtml(title)}"><span></span></button></div>`).join('')}${actions ? `<div class="inline-actions">${actions}</div>` : ''}`;
}

function explorerView() {
  const c = state.containers[state.currentContainer];
  const locked = c.status === 'Bloqueado';
  if (locked) return `${header(c.name, 'Este container está bloqueado.', `<button class="button-primary" data-action="unlock-container">${icon('unlock')} Desbloquear</button>`)}<div class="card empty-state protected">${icon('lock')}<strong>Conteúdo protegido</strong><p>Desbloqueie o container para visualizar os arquivos.</p></div>`;
  const currentFolder = state.nativeFolder;
  const visibleFolders = state.nativePath ? state.nativeFolders.filter(folder => folderParent(folder) === currentFolder) : [];
  const visibleObjects = state.nativePath ? state.nativeObjects.filter(object => folderParent(object.name) === currentFolder) : [];
  const rows = state.nativePath
    ? visibleFolders.map(folder => `<div class="list-row"><button class="container-link" data-action="open-folder" data-folder="${escapeHtml(folder)}"><span class="container-icon">${icon('folder')}</span><span class="row-main"><strong>${escapeHtml(folderName(folder))}</strong><span>Pasta virtual criptografada</span></span></button><div class="row-end"><span>—</span></div><div class="row-end">${pill('Local', 'green')}</div><div class="row-end"><button class="mini-button" data-action="rename-folder" data-folder="${escapeHtml(folder)}">Renomear</button><button class="mini-button" data-action="delete-folder" data-folder="${escapeHtml(folder)}">Excluir</button></div></div>`).join('') + visibleObjects.map(object => {
        const image = /\.(png|jpe?g|webp)$/i.test(object.name);
        return `<div class="list-row"><button class="container-link" data-action="${image ? 'preview-file' : 'export-file'}" data-object-id="${escapeHtml(object.id)}"><span class="container-icon ${image ? '' : 'warm'}">${icon('file')}</span><span class="row-main"><strong>${escapeHtml(folderName(object.name))}</strong><span>${formatBytes(object.plaintext_len)} · ${object.block_count} blocos</span></span></button><div class="row-end"><span>${formatBytes(object.plaintext_len)}</span></div><div class="row-end">${pill('Local', 'green')}</div><div class="row-end"><button class="mini-button" data-action="rename-object" data-object-id="${escapeHtml(object.id)}">Renomear</button><button class="mini-button" data-action="copy-object" data-object-id="${escapeHtml(object.id)}">Copiar</button><button class="mini-button" data-action="delete-object" data-object-id="${escapeHtml(object.id)}">Excluir</button></div></div>`;
      }).join('')
    : [['Projetos', 'Pasta', 'Hoje'], ['Imagens', 'Pasta', 'Hoje'], ['Apresentação 2026.pdf', '2,4 MB', 'Hoje'], ['planejamento-q4.xlsx', '847 KB', 'Ontem'], ['notas-privadas.md', '28 KB', '12 out']].map((file, index) => `<div class="list-row"><button class="container-link" data-action="${index < 2 ? 'new-folder' : 'preview-file'}"><span class="container-icon ${index < 2 ? '' : 'warm'}">${index < 2 ? icon('folder') : icon('file')}</span><span class="row-main"><strong>${escapeHtml(file[0])}</strong><span>${escapeHtml(file[1])}</span></span></button><div class="row-end"><span>${index < 2 ? '—' : escapeHtml(file[1])}</span></div><div class="row-end">${pill(index < 2 ? 'Local' : 'Disponível', 'green')}</div><button class="icon-button row-menu">•••</button></div>`).join('');
  const count = state.nativePath ? visibleObjects.length + visibleFolders.length : c.files;
  const breadcrumb = currentFolder ? `<button class="filter-tab" data-action="go-up-folder">${escapeHtml(c.name)}</button><svg viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg><strong>${escapeHtml(currentFolder)}</strong>` : `<button class="filter-tab active">${escapeHtml(c.name)}</button><svg viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></svg><strong>Todos os arquivos</strong>`;
  return `${header(c.name, `${count} itens · ${escapeHtml(c.size)} utilizados`, `<div class="inline-actions"><button class="button-secondary" data-action="new-folder">${icon('folder')} Nova pasta</button><button class="button-primary" data-action="import-files">${icon('upload')} Importar arquivos</button></div>`)}<div class="toolbar"><div class="breadcrumb">${breadcrumb}</div><div class="search-box">${icon('search')}<input type="search" placeholder="Pesquisar neste container" data-filter="objects" /></div></div><div class="card list-card"><div class="list-header"><span>Nome</span><span>Tamanho</span><span>Disponibilidade</span><span></span></div>${rows || '<div class="empty-state">Nenhum arquivo importado.</div>'}</div>`;
}

function render() {
  const names = { home: ['Início', 'Visão geral'], containers: ['Meus containers', 'Todos'], shares: ['Compartilhamentos', 'Ativos'], transfers: ['Transferências', 'Em andamento'], settings: ['Configurações', 'Segurança'], explorer: [state.containers[state.currentContainer]?.name || 'Container', 'Arquivos'] };
  const [section, current] = names[state.view] || names.home;
  document.querySelector('#breadcrumb-section').textContent = section;
  document.querySelector('#breadcrumb-current').textContent = current;
  const containerCount = document.querySelector('[data-view="containers"] em'); if (containerCount) containerCount.textContent = state.containers.length;
  view.innerHTML = ({ home: homeView, containers: containersView, shares: sharesView, transfers: transfersView, settings: settingsView, explorer: explorerView }[state.view])();
  document.querySelectorAll('.nav-item').forEach(button => button.classList.toggle('active', button.dataset.view === (state.view === 'explorer' ? 'containers' : state.view)));
}

function showModal(content, wide = false) { modal.className = `modal${wide ? ' wide' : ''}`; modal.innerHTML = content; modalBackdrop.hidden = false; document.body.style.overflow = 'hidden'; const focusable = modal.querySelector('input, button'); if (focusable) setTimeout(() => focusable.focus(), 0); }
function closeModal() { modalBackdrop.hidden = true; document.body.style.overflow = ''; }
function toast(message, error = false) { const node = document.createElement('div'); node.className = `toast${error ? ' error' : ''}`; node.insertAdjacentHTML('afterbegin', icon(error ? 'warning' : 'check')); const text = document.createElement('span'); text.textContent = message; node.append(text); document.querySelector('.toast-region').append(node); setTimeout(() => node.remove(), 3400); }
async function importNativeFiles(paths) {
  let imported = 0;
  for (const sourcePath of paths) {
    const fileName = sourcePath.split(/[\\/]/).pop();
    try {
      const name = state.nativeFolder ? `${state.nativeFolder}/${fileName}` : fileName;
      const object = await nativeInvoke('import_file', { sourcePath, name });
      state.nativeObjects.push(object);
      state.activity.unshift({ kind: 'upload', icon: 'upload', title: 'Arquivo importado', detail: name });
      imported += 1;
    } catch (error) { toast(`${fileName}: ${String(error)}`, true); }
  }
  state.containers[state.currentContainer].files = state.nativeObjects.length;
  if (imported) toast(`${imported} arquivo(s) importado(s) com criptografia em streaming.`);
  if (state.view === 'explorer') render();
}

async function importFiles() {
  if (!nativeInvoke || !state.nativePath) { filePicker.click(); return; }
  const dialog = window.__TAURI__?.dialog;
  if (!dialog) { toast('Seleção de arquivos disponível no aplicativo desktop.', true); return; }
  try {
    const selected = await dialog.open({ multiple: true, directory: false });
    if (selected) await importNativeFiles(Array.isArray(selected) ? selected : [selected]);
  } catch (error) { toast(String(error), true); }
}

async function selectContainerPath(target, mode) {
  const dialog = window.__TAURI__?.dialog;
  if (!dialog) { toast('Seleção de caminho disponível no aplicativo desktop.', true); return; }
  try {
    const path = mode === 'create' ? await dialog.save() : await dialog.open({ directory: true, multiple: false });
    if (typeof path === 'string') document.querySelector(`#${target}`).value = path;
  } catch (error) { toast(String(error), true); }
}

async function previewObject(objectId) {
  if (!nativeInvoke || !state.nativePath) { toast('Visualização protegida disponível no aplicativo desktop.'); return; }
  try {
    const preview = await nativeInvoke('preview_image', { objectId });
    showModal(`<div class="modal-head"><div><h2>Visualização protegida</h2><p>Pixels decodificados em memória; o arquivo original não foi exportado.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><canvas id="image-preview" class="image-preview" aria-label="Imagem protegida"></canvas>` , true);
    const canvas = document.querySelector('#image-preview');
    canvas.width = preview.width; canvas.height = preview.height;
    canvas.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(preview.pixels), preview.width, preview.height), 0, 0);
  } catch (error) { toast(String(error), true); }
}

async function exportObject(objectId) {
  if (!nativeInvoke || !state.nativePath) { toast('Exportação disponível no aplicativo desktop.'); return; }
  const destinationPath = window.prompt('Caminho de destino para a cópia desprotegida:');
  if (!destinationPath) return;
  try { await nativeInvoke('export_file', { objectId, destinationPath }); toast('Arquivo exportado. A cópia não está protegida pelo container.'); }
  catch (error) { toast(String(error), true); }
}

async function renameObject(objectId) {
  if (!nativeInvoke || !state.nativePath) { toast('Renomeação disponível no aplicativo desktop.'); return; }
  const object = state.nativeObjects.find(candidate => candidate.id === objectId);
  const name = window.prompt('Novo nome ou caminho virtual:', object?.name || '');
  if (!name || name === object?.name) return;
  try {
    const updated = await nativeInvoke('rename_object', { objectId, name });
    state.nativeObjects = state.nativeObjects.map(candidate => candidate.id === objectId ? updated : candidate);
    state.activity.unshift({ kind: 'upload', icon: 'file', title: 'Objeto renomeado', detail: updated.name });
    toast('Objeto renomeado.'); render();
  } catch (error) { toast(String(error), true); }
}

async function copyObject(objectId) {
  if (!nativeInvoke || !state.nativePath) { toast('Cópia disponível no aplicativo desktop.'); return; }
  const object = state.nativeObjects.find(candidate => candidate.id === objectId);
  const name = window.prompt('Nome ou caminho virtual da cópia:', object?.name ? `${object.name}.copy` : 'copia');
  if (!name) return;
  try { const copied = await nativeInvoke('copy_object', { objectId, name }); state.nativeObjects.push(copied); state.containers[state.currentContainer].files = state.nativeObjects.length; state.activity.unshift({ kind: 'upload', icon: 'file', title: 'Arquivo copiado', detail: copied.name }); toast('Cópia criada com nova chave de conteúdo.'); render(); }
  catch (error) { toast(String(error), true); }
}

async function deleteObject(objectId) {
  if (!nativeInvoke || !state.nativePath) { toast('Exclusão disponível no aplicativo desktop.'); return; }
  const object = state.nativeObjects.find(candidate => candidate.id === objectId);
  if (!object || !window.confirm(`Excluir "${object.name}" do container?`)) return;
  try {
    await nativeInvoke('delete_object', { objectId });
    state.nativeObjects = state.nativeObjects.filter(candidate => candidate.id !== objectId);
    state.containers[state.currentContainer].files = state.nativeObjects.length;
    state.activity.unshift({ kind: 'upload', icon: 'close', title: 'Objeto excluído', detail: object.name });
    toast('Objeto removido do índice.'); render();
  } catch (error) { toast(String(error), true); }
}

async function createFolder() {
  if (!nativeInvoke || !state.nativePath) { toast('Pastas disponíveis no aplicativo desktop.'); return; }
  const name = window.prompt('Nome da nova pasta virtual:');
  if (!name) return;
  const path = state.nativeFolder ? `${state.nativeFolder}/${name}` : name;
  try { state.nativeFolders = await nativeInvoke('create_folder', { path }); state.activity.unshift({ kind: 'upload', icon: 'folder', title: 'Pasta criada', detail: path }); toast('Pasta criada.'); render(); }
  catch (error) { toast(String(error), true); }
}

async function renameFolder(oldPath) {
  const newPath = window.prompt('Novo nome ou caminho da pasta:', oldPath);
  if (!newPath || newPath === oldPath) return;
  try { state.nativeFolders = await nativeInvoke('rename_folder', { oldPath, newPath }); toast('Pasta renomeada.'); render(); }
  catch (error) { toast(String(error), true); }
}

async function deleteFolder(path) {
  if (!window.confirm(`Excluir "${path}" e todo o conteúdo virtual abaixo?`)) return;
  try { state.nativeFolders = await nativeInvoke('delete_folder', { path }); toast('Pasta removida.'); render(); }
  catch (error) { toast(String(error), true); }
}

function newContainerModal() {
  showModal(`<div class="modal-head"><div><h2>Novo container</h2><p>Crie um espaço criptografado para manter seus arquivos sob controle.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><form id="new-container-form" class="form-grid"><div class="field"><label for="container-name">Nome de apresentação</label><input id="container-name" name="name" placeholder="Ex.: Documentos pessoais" required /></div><div class="field"><label for="container-location">Local no dispositivo</label><div class="path-picker"><input id="container-location" name="location" placeholder="Caminho completo para o diretório .vault" required /><button type="button" class="button-secondary" data-action="select-container-path" data-target="container-location" data-mode="create">Escolher</button></div><small>O container será criado como um diretório .vault opaco. Os nomes dos arquivos não são derivados dos seus dados.</small></div><div class="field"><label for="container-password">Senha principal</label><input id="container-password" type="password" name="password" placeholder="Mínimo de 12 caracteres" minlength="12" required /></div><div class="field"><label for="container-password-confirm">Confirmar senha</label><input id="container-password-confirm" type="password" name="confirm" required /></div><div class="field"><label for="container-keyfile">Keyfile opcional</label><input id="container-keyfile" name="keyfile" placeholder="Caminho do arquivo-chave" /><small>O arquivo não é copiado; será necessário para desbloquear este container.</small></div><label class="checkbox-row"><input type="checkbox" name="autoLock" checked /> Bloquear automaticamente após 15 minutos</label><div class="warning-box">${icon('warning')}<span>A recovery key será exibida uma única vez na próxima etapa. Sem ela ou a senha, os dados não podem ser recuperados.</span></div><div class="modal-footer"><button type="button" class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" type="submit">Criar e gerar recovery key ${icon('arrow')}</button></div></form>`);
}

function recoveryModal(name, recoveryKey = demoRecoveryKey()) {
  showModal(`<div class="modal-head"><div><h2>Guarde sua recovery key</h2><p>Ela é a única forma de recuperar “${escapeHtml(name)}” sem a senha principal.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><div class="recovery-box"><p>Anote esta chave e guarde-a em um local seguro. Ela não será exibida novamente.</p><code class="recovery-key">${escapeHtml(recoveryKey)}</code></div><div class="modal-spacer"></div><label class="checkbox-row"><input id="recovery-confirm" type="checkbox" /> Eu guardei minha recovery key em um local seguro.</label><div class="modal-footer"><button class="button-primary" data-action="finish-recovery" disabled>Concluir criação ${icon('check')}</button></div></div>`);
}

function demoRecoveryKey() {
  const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('').match(/.{1,4}/g).join('-').toUpperCase();
}

function unlockModal(path = state.nativePath || '') { showModal(`<div class="lock-dialog"><div class="lock-symbol">${icon('unlock')}</div><h2>Desbloquear container</h2><p>Digite o caminho, a senha e, se configurado, o keyfile.</p><div class="field"><label for="unlock-path">Diretório do container</label><div class="path-picker"><input id="unlock-path" value="${escapeHtml(path)}" placeholder="Caminho completo para o diretório .vault" /><button type="button" class="button-secondary" data-action="select-container-path" data-target="unlock-path" data-mode="open">Escolher</button></div></div><div class="field"><label for="unlock-password">Senha principal</label><input id="unlock-password" type="password" placeholder="Sua senha" /></div><div class="field"><label for="unlock-keyfile">Keyfile opcional</label><input id="unlock-keyfile" placeholder="Caminho do arquivo-chave" /></div><div class="modal-footer"><button class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" data-action="confirm-unlock">Desbloquear ${icon('arrow')}</button></div><button class="mini-button recovery-link" data-action="recovery-unlock">Usar recovery key</button></div>`); }
function recoveryUnlockModal(path = state.nativePath || '') { showModal(`<div class="lock-dialog"><div class="lock-symbol">${icon('unlock')}</div><h2>Usar recovery key</h2><p>A recovery key abre o container sem a senha principal.</p><div class="field"><label for="recovery-path">Diretório do container</label><div class="path-picker"><input id="recovery-path" value="${escapeHtml(path)}" placeholder="Caminho completo para o diretório .vault" /><button type="button" class="button-secondary" data-action="select-container-path" data-target="recovery-path" data-mode="open">Escolher</button></div></div><div class="field"><label for="recovery-key-input">Recovery key</label><input id="recovery-key-input" autocomplete="off" placeholder="Cole a recovery key" /></div><div class="modal-footer"><button class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" data-action="confirm-recovery-unlock">Desbloquear ${icon('arrow')}</button></div></div>`); }
function shareModal() {
  const object = state.nativeObjects[0];
  const unavailable = !nativeInvoke || !state.nativePath || !object;
  showModal(`<div class="modal-head"><div><h2>Novo compartilhamento</h2><p>O convite é selado no Rust; a UI nunca recebe a CEK nem a Participation Key.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><form id="share-form" class="form-grid">${object ? `<div class="field"><label>Arquivo</label><div class="contact-option selected full-width"><span class="container-icon warm">${icon('file')}</span><span class="row-main"><strong>${escapeHtml(object.name)}</strong><span>${formatBytes(object.plaintext_len)} · ${object.block_count} blocos</span></span></div><input type="hidden" id="share-object-id" value="${escapeHtml(object.id)}" /></div>` : `<div class="warning-box">${icon('warning')}<span>Desbloqueie um container com arquivo importado antes de criar um convite.</span></div>`}<div class="field"><label for="contact-card">Cartão de contato (hex)</label><textarea id="contact-card" class="invitation-output contact-card-input" autocomplete="off" placeholder="Cole o cartão de contato codificado em hexadecimal" ${unavailable ? 'disabled' : 'required'}></textarea><button type="button" class="mini-button" data-action="inspect-contact" ${unavailable ? 'disabled' : ''}>Ver fingerprint</button><small id="contact-fingerprint">O fingerprint será calculado localmente pelo backend antes da emissão.</small></div><label class="checkbox-row"><input id="contact-verified" type="checkbox" ${unavailable ? 'disabled' : ''} /> Confirmei este fingerprint por um canal externo.</label><div class="field"><label for="relay-endpoint">Endpoint do relay privado</label><input id="relay-endpoint" inputmode="url" autocomplete="off" placeholder="127.0.0.1:9000" ${unavailable ? 'disabled' : 'required'} /><small>Conexões diretas não são usadas.</small></div><div class="field"><label for="invite-expiry">Validade</label><select id="invite-expiry" ${unavailable ? 'disabled' : ''}><option value="604800">7 dias</option><option value="86400">1 dia</option><option value="2592000">30 dias</option></select></div><div class="field"><label>Permissões</label><label class="checkbox-row"><input id="permission-download" type="checkbox" checked disabled /> Download</label><label class="checkbox-row"><input id="permission-seed" type="checkbox" ${unavailable ? 'disabled' : ''} /> Semeadura</label></div><div class="warning-box">${icon('warning')}<span>O convite concede acesso a qualquer portador até expirar ou ser revogado.</span></div><div class="modal-footer"><button type="button" class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" type="submit" ${unavailable ? 'disabled' : ''}>Gerar convite ${icon('share')}</button></div></form>`);
}

function invitationModal(created) { const relay = created.relay_hints[0] || ''; showModal(`<div class="modal-head"><div><h2>Convite gerado</h2><p>Envie este blob por um canal seguro. Ele não contém material em claro fora da criptografia HPKE.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><textarea id="invitation-output" class="invitation-output" readonly>${escapeHtml(created.invitation)}</textarea><div class="modal-footer"><button class="button-secondary" data-action="copy-invitation">Copiar blob</button><button class="button-secondary" data-action="seed-invitation" data-invitation="${escapeHtml(created.invitation)}" data-object-id="${escapeHtml(created.object_id)}" data-swarm-id="${escapeHtml(created.swarm_id)}" data-relay="${escapeHtml(relay)}">Ativar seeding</button><button class="button-secondary" data-action="revoke-swarm" data-swarm-id="${escapeHtml(created.swarm_id)}">Revogar acesso futuro</button><button class="button-primary" data-action="close-modal">Concluir ${icon('check')}</button></div>`); }
function contactCardModal() { showModal(`<div class="modal-head"><div><h2>Cartão de contato</h2><p>Compartilhe somente este cartão público. A chave privada permanece no container.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><form id="contact-card-form" class="form-grid"><div class="field"><label for="contact-name">Nome sugerido</label><input id="contact-name" required maxlength="128" /></div><div class="modal-footer"><button type="button" class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" type="submit">Gerar cartão ${icon('arrow')}</button></div></form>`); }
function contactCardResultModal(card) { showModal(`<div class="modal-head"><div><h2>Cartão pronto</h2><p>Envie o cartão completo por um canal seguro. O destinatário deve confirmar o fingerprint antes de compartilhar.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><textarea id="contact-card-output" class="invitation-output" readonly>${escapeHtml(card)}</textarea><div class="modal-footer"><button class="button-secondary" data-action="copy-contact-card">Copiar cartão</button><button class="button-primary" data-action="close-modal">Concluir ${icon('check')}</button></div>`); }
function openInvitationModal() { showModal(`<div class="modal-head"><div><h2>Abrir convite</h2><p>O convite será validado dentro do container. Chaves de conteúdo não serão entregues à interface.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><form id="open-invitation-form" class="form-grid"><div class="field"><label for="invitation-input">Blob do convite (hex)</label><textarea id="invitation-input" class="invitation-output" required></textarea></div><div class="modal-footer"><button type="button" class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-primary" type="submit">Validar convite ${icon('arrow')}</button></div></form>`); }
function invitationSummaryModal(summary, invitationHex) { const relay = summary.relay_hints[0] || ''; showModal(`<div class="modal-head"><div><h2>Convite validado</h2><p>O owner e a capability foram verificados. O download ocorrerá somente pelo relay indicado.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><div class="form-grid"><div class="contact-option selected full-width"><span class="row-main"><strong>Owner ${escapeHtml(summary.owner_fingerprint)}</strong><span>Objeto ${escapeHtml(summary.object_id)} · Swarm ${escapeHtml(summary.swarm_id)}</span></span></div><div class="warning-box">${icon('warning')}<span>Relay: ${escapeHtml(summary.relay_hints.join(', '))}. Expira em ${new Date(summary.expires * 1000).toLocaleString('pt-BR')}.</span></div><small id="source-status">Fontes não consultadas.</small><div class="modal-footer"><button class="button-secondary" data-action="close-modal">Cancelar</button><button class="button-secondary" data-action="query-discovery" data-invitation="${escapeHtml(invitationHex)}">Consultar fontes</button><button class="button-secondary" data-action="publish-discovery" data-invitation="${escapeHtml(invitationHex)}" data-relay="${escapeHtml(relay)}">Publicar presença</button><button id="download-invitation-button" class="button-primary" data-action="download-invitation" data-invitation="${escapeHtml(invitationHex)}" data-relay="${escapeHtml(relay)}" data-rendezvous="">Iniciar download ${icon('download')}</button></div></div>`); }

document.addEventListener('click', event => {
  const nav = event.target.closest('[data-view]'); if (nav) { state.view = nav.dataset.view; render(); return; }
  const settings = event.target.closest('[data-settings-tab]'); if (settings) { state.settingsTab = settings.dataset.settingsTab; render(); return; }
  const toggle = event.target.closest('[data-toggle]'); if (toggle) { toggle.classList.toggle('on'); if (toggle.dataset.setting === 'Bloqueio automático') { state.autoLock = toggle.classList.contains('on'); scheduleAutoLock(); } return; }
  const contact = event.target.closest('[data-contact]'); if (contact) { document.querySelectorAll('[data-contact]').forEach(option => option.classList.toggle('selected', option === contact)); state.selectedContact = contact.dataset.contact; return; }
  const action = event.target.closest('[data-action]'); if (!action) return;
  event.preventDefault();
  const handlers = {
    'new-container': newContainerModal,
    'select-container-path': () => selectContainerPath(action.dataset.target, action.dataset.mode),
    'close-modal': closeModal,
    'show-containers': () => { state.view = 'containers'; render(); },
    'show-transfers': () => { state.view = 'transfers'; render(); },
    'show-settings': () => { state.view = 'settings'; render(); },
    'new-share': shareModal,
    'open-invitation': openInvitationModal,
    'create-contact-card': contactCardModal,
    'rename-object': () => renameObject(action.dataset.objectId),
    'copy-object': () => copyObject(action.dataset.objectId),
    'delete-object': () => deleteObject(action.dataset.objectId),
    'download-invitation': async () => {
      try {
        const object = await nativeInvoke('download_invitation', { invitationHex: action.dataset.invitation, relayEndpoint: action.dataset.relay, rendezvousEndpoint: action.dataset.rendezvous || null });
        state.nativeObjects.push(object);
        state.containers[state.currentContainer].files = state.nativeObjects.length;
        state.activity.unshift({ kind: 'download', icon: 'download', title: 'Download concluído', detail: object.name });
        if (nativeInvoke && window.confirm('O convite autoriza seeding. Manter este objeto disponível para outros participantes?')) { await nativeInvoke('seed_invitation', { invitationHex: action.dataset.invitation, relayEndpoint: action.dataset.relay }); }
        closeModal(); toast('Objeto recebido e validado pelo relay.'); render();
      } catch (error) { toast(String(error), true); }
    },
    'query-discovery': async () => {
      const rendezvousEndpoint = window.prompt('Endpoint HTTP do rendezvous:');
      if (!rendezvousEndpoint) return;
      try {
        const sources = await nativeInvoke('query_discovery', { invitationHex: action.dataset.invitation, rendezvousEndpoint });
        const status = document.querySelector('#source-status');
        if (status) status.textContent = `${sources.length} fonte(s) encontrada(s).`;
        const download = document.querySelector('#download-invitation-button');
        if (download && sources[0]) { download.dataset.relay = sources[0].relay_endpoint; download.dataset.rendezvous = rendezvousEndpoint; }
      } catch (error) { toast(String(error), true); }
    },
    'publish-discovery': async () => {
      const rendezvousEndpoint = window.prompt('Endpoint HTTP do rendezvous:');
      if (!rendezvousEndpoint) return;
      try { await nativeInvoke('publish_discovery', { invitationHex: action.dataset.invitation, rendezvousEndpoint, relayEndpoint: action.dataset.relay }); toast('Presença publicada por até 15 minutos.'); } catch (error) { toast(String(error), true); }
    },
    'seed-invitation': async () => {
      if (!window.confirm('O seeding manterá os blocos disponíveis enquanto o app estiver aberto. Continuar?')) return;
      try { if (action.dataset.invitation) await nativeInvoke('seed_invitation', { invitationHex: action.dataset.invitation, relayEndpoint: action.dataset.relay }); else await nativeInvoke('seed_object', { objectId: action.dataset.objectId, swarmId: action.dataset.swarmId, relayEndpoint: action.dataset.relay }); closeModal(); toast('Seeding iniciado pelo relay privado.'); } catch (error) { toast(String(error), true); }
    },
    'revoke-swarm': async () => {
      if (!window.confirm('Revogar este swarm impedirá novas conexões em seeders deste container. Cópias já baixadas não serão apagadas. Continuar?')) return;
      try { const epoch = await nativeInvoke('revoke_swarm', { swarmId: action.dataset.swarmId }); toast(`Swarm revogado na época ${epoch}.`); } catch (error) { toast(String(error), true); }
    },
    'change-password': async () => {
      const first = window.prompt('Nova senha (mínimo de 12 caracteres):');
      if (first === null) return;
      const second = window.prompt('Confirme a nova senha:');
      if (first !== second) { toast('As senhas não coincidem.', true); return; }
      const keyfilePath = window.prompt('Caminho do keyfile atual (deixe vazio se não houver):');
      if (keyfilePath === null) return;
      try { await nativeInvoke('change_password', { password: first, keyfilePath: keyfilePath.trim() || null }); toast('Senha alterada.'); } catch (error) { toast(String(error), true); }
    },
    'rotate-recovery': async () => {
      if (!window.confirm('A recovery key anterior será invalidada. Continuar?')) return;
      try {
        const key = await nativeInvoke('rotate_recovery_key');
        showModal(`<div class="modal-head"><div><h2>Nova recovery key</h2><p>A chave anterior foi invalidada. Guarde esta chave; ela não será exibida novamente.</p></div><button class="close-button" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><div class="recovery-box"><code class="recovery-key">${escapeHtml(key)}</code></div><div class="modal-footer"><button class="button-primary" data-action="close-modal">Concluir ${icon('check')}</button></div>`);
      } catch (error) { toast(String(error), true); }
    },
    'rotate-cmk': async () => {
      const password = window.prompt('Senha atual:');
      if (password === null) return;
      const recoveryKey = window.prompt('Recovery key atual:');
      if (recoveryKey === null) return;
      const keyfilePath = window.prompt('Caminho do keyfile atual (deixe vazio se não houver):');
      if (keyfilePath === null) return;
      if (!window.confirm('A CMK, o índice e a identidade serão recriptografados. Continuar?')) return;
      try { await nativeInvoke('rotate_cmk', { password, recoveryKey, keyfilePath: keyfilePath.trim() || null }); toast('CMK rotacionada.'); } catch (error) { toast(String(error), true); }
    },
    'export-backup': async () => {
      const destinationPath = window.prompt('Caminho para salvar o backup cifrado do header:');
      if (!destinationPath) return;
      try { await nativeInvoke('export_header_backup', { destinationPath }); toast('Backup do header exportado.'); } catch (error) { toast(String(error), true); }
    },
    'restore-backup': async () => {
      const path = window.prompt('Caminho do container a recuperar:');
      const backupPath = window.prompt('Caminho do backup do header:');
      if (!path || !backupPath || !window.confirm('Restaurar o header e a identidade deste container?')) return;
      try { await nativeInvoke('restore_header_backup', { path, backupPath }); toast('Backup restaurado. Desbloqueie o container para validar a recuperação.'); } catch (error) { toast(String(error), true); }
    },
    'compact-container': async () => {
      if (!window.confirm('A compactação reescreverá os segmentos e removerá blocos órfãos. Continuar?')) return;
      try { await nativeInvoke('compact_container'); toast('Segmentos compactados.'); } catch (error) { toast(String(error), true); }
    },
    'lock-container': async () => {
      if (nativeInvoke && state.nativePath) { try { await nativeInvoke('lock_container'); } catch (error) { toast(String(error), true); return; } }
      state.containers[state.currentContainer].status = 'Bloqueado'; state.nativeObjects = []; state.nativeFolders = []; state.nativeFolder = ''; clearTimeout(autoLockTimer); toast('Container bloqueado. Chaves e sessões foram descartadas.'); render();
    },
    'unlock-container': unlockModal,
    'confirm-unlock': async () => {
      const path = document.querySelector('#unlock-path')?.value.trim() || '';
      const password = document.querySelector('#unlock-password')?.value || '';
      const keyfilePath = document.querySelector('#unlock-keyfile')?.value.trim() || '';
      if (!path) { toast('Informe o diretório do container.', true); return; }
      if (nativeInvoke) { try { adoptNativeContainer(path, await nativeInvoke('unlock_container', { path, password, keyfilePath: keyfilePath || null })); await refreshNativeFolders(); } catch (error) { toast(String(error), true); return; } }
      if (!nativeInvoke) state.containers[state.currentContainer].status = 'Desbloqueado'; closeModal(); scheduleAutoLock(); toast('Container desbloqueado com sucesso.'); render();
    },
    'recovery-unlock': recoveryUnlockModal,
    'confirm-recovery-unlock': async () => {
      const path = document.querySelector('#recovery-path')?.value.trim() || '';
      const recoveryKey = document.querySelector('#recovery-key-input')?.value.trim() || '';
      if (!path || !recoveryKey) { toast('Informe o diretório e a recovery key.', true); return; }
      if (nativeInvoke) { try { adoptNativeContainer(path, await nativeInvoke('unlock_container_recovery', { path, recoveryKey })); await refreshNativeFolders(); } catch (error) { toast(String(error), true); return; } }
      if (!nativeInvoke) state.containers[state.currentContainer].status = 'Desbloqueado'; closeModal(); scheduleAutoLock(); toast('Container desbloqueado com a recovery key.'); render();
    },
    'open-container': async () => { state.currentContainer = Number(action.dataset.containerIndex || 0); const container = state.containers[state.currentContainer]; if (container.status === 'Bloqueado') { unlockModal(container.nativePath); return; } if (nativeInvoke && container.nativePath) { try { await nativeInvoke('activate_container', { path: container.nativePath }); adoptNativeContainer(container.nativePath, await nativeInvoke('list_objects')); await refreshNativeFolders(); } catch (error) { toast(String(error), true); return; } } state.view = 'explorer'; render(); },
    'import-files': importFiles,
    'new-folder': createFolder,
    'open-folder': () => { state.nativeFolder = action.dataset.folder; render(); },
    'go-up-folder': () => { state.nativeFolder = folderParent(state.nativeFolder); render(); },
    'rename-folder': () => renameFolder(action.dataset.folder),
    'delete-folder': () => deleteFolder(action.dataset.folder),
    'preview-file': () => previewObject(action.dataset.objectId),
    'export-file': () => exportObject(action.dataset.objectId),
    'inspect-contact': async () => { const cardHex = document.querySelector('#contact-card')?.value.replace(/\s+/g, '').trim() || ''; if (!/^(?:[0-9a-fA-F]{2})+$/.test(cardHex)) { toast('Cole um cartão hexadecimal válido.', true); return; } try { const contact = await nativeInvoke('decode_contact_card', { cardHex }); const target = document.querySelector('#contact-fingerprint'); target.textContent = `${contact.name} · Fingerprint ${contact.fingerprint}`; } catch (error) { toast(String(error), true); } },
    'copy-invitation': async () => { try { await navigator.clipboard.writeText(document.querySelector('#invitation-output').value); toast('Blob copiado.'); } catch (error) { toast(String(error), true); } },
    'copy-contact-card': async () => { try { await navigator.clipboard.writeText(document.querySelector('#contact-card-output').value); toast('Cartão copiado.'); } catch (error) { toast(String(error), true); } },
    'finish-recovery': () => { closeModal(); toast('Container criado e protegido com sucesso.'); state.view = 'containers'; render(); },
  };
  if (handlers[action.dataset.action]) handlers[action.dataset.action]();
});

document.addEventListener('change', event => {
  if (event.target.id === 'recovery-confirm') { const button = document.querySelector('[data-action="finish-recovery"]'); if (button) button.disabled = !event.target.checked; }
});

document.addEventListener('input', event => {
  const term = event.target.value.toLowerCase().trim();
  if (event.target.dataset.filter === 'containers') document.querySelectorAll('[data-container-row]').forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(term); });
  if (event.target.dataset.filter === 'objects') document.querySelectorAll('.list-card .list-row').forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(term); });
});

document.addEventListener('submit', event => {
  if (event.target.id === 'open-invitation-form') {
    event.preventDefault();
    const invitationHex = document.querySelector('#invitation-input')?.value.replace(/\s+/g, '').trim() || '';
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(invitationHex)) { toast('O convite deve ser hexadecimal.', true); return; }
    (async () => { try { invitationSummaryModal(await nativeInvoke('open_invitation', { invitationHex }), invitationHex); } catch (error) { toast(String(error), true); } })();
    return;
  }
  if (event.target.id === 'contact-card-form') {
    event.preventDefault();
    const name = document.querySelector('#contact-name')?.value.trim() || '';
    (async () => { try { contactCardResultModal(await nativeInvoke('create_contact_card', { name })); } catch (error) { toast(String(error), true); } })();
    return;
  }
  if (event.target.id === 'share-form') {
    event.preventDefault();
    const objectId = document.querySelector('#share-object-id')?.value || '';
    const cardHex = document.querySelector('#contact-card')?.value.replace(/\s+/g, '').trim() || '';
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(cardHex)) { toast('O cartão de contato deve ser hexadecimal.', true); return; }
    if (!document.querySelector('#contact-verified')?.checked) { toast('Confirme o fingerprint do contato antes de emitir o convite.', true); return; }
    const permissions = 1 | (document.querySelector('#permission-seed')?.checked ? 2 : 0);
    const expiresInSeconds = Number(document.querySelector('#invite-expiry')?.value || 604800);
    const relayEndpoint = document.querySelector('#relay-endpoint')?.value.trim() || '';
    if (!relayEndpoint) { toast('Informe o endpoint do relay privado.', true); return; }
    (async () => { try { const contact = await nativeInvoke('decode_contact_card', { cardHex }); const invitation = await nativeInvoke('create_invitation', { objectId, recipientHpkePublic: contact.hpke_public, permissions, expiresInSeconds, relayHints: [relayEndpoint] }); const object = state.nativeObjects.find(candidate => candidate.id === objectId); state.invitations.unshift({ recipient: contact.name, objectName: object?.name || 'Objeto', seed: Boolean(permissions & 2), expires: expiresInSeconds === 604800 ? '7 dias' : expiresInSeconds === 86400 ? '1 dia' : '30 dias' }); state.activity.unshift({ kind: 'share', icon: 'share', title: 'Convite gerado', detail: `${object?.name || 'Objeto'} · ${contact.name}` }); invitationModal(invitation); } catch (error) { toast(String(error), true); } })();
    return;
  }
  if (event.target.id !== 'new-container-form') return;
  event.preventDefault(); const data = new FormData(event.target); const name = String(data.get('name')).trim();
  if (data.get('password') !== data.get('confirm')) { toast('As senhas não coincidem.', true); return; }
  const location = String(data.get('location')).trim(); const password = String(data.get('password')); const keyfilePath = String(data.get('keyfile') || '').trim() || null;
  const create = async () => {
    let recoveryKey;
    try { recoveryKey = nativeInvoke ? await nativeInvoke('create_container', { path: location, password, keyfilePath }) : undefined; }
    catch (error) { toast(String(error), true); return; }
    state.nativePath = location;
    state.nativeObjects = [];
    state.nativeFolders = [];
    state.nativeFolder = '';
    state.containers.unshift({ name, path: 'Ainda vazio', size: '0 B', updated: 'Agora', status: 'Desbloqueado', color: 'green', files: 0, nativePath: location });
    state.currentContainer = 0;
    scheduleAutoLock();
    closeModal(); recoveryModal(name, recoveryKey); 
  };
  create();
});

filePicker.addEventListener('change', async event => {
  const files = Array.from(event.target.files || []);
  if (!files.length) return;
  toast(`${files.length} ${files.length === 1 ? 'arquivo selecionado' : 'arquivos selecionados'} no modo demonstrativo.`);
  event.target.value = '';
});
modalBackdrop.addEventListener('click', event => { if (event.target === modalBackdrop) closeModal(); });
document.addEventListener('click', () => scheduleAutoLock(), { passive: true });
document.addEventListener('keydown', () => scheduleAutoLock(), { passive: true });
render();
