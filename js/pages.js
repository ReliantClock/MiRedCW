// ============================================================
//  RedCW — Page Loaders
// ============================================================

/* ── INICIO ─────────────────────────────────────────────────── */
async function loadInicioPage() {
  const feed = document.getElementById("inicio-feed");
  if (!feed) return;
  feed.innerHTML = skeletonPosts(3);

  try {
    const posts = await dbSelect("posts", {
      eq: { section: "inicio" },
      order: "created_at",
      limit: 30,
      select: "*, profiles(username, avatar_url, plan, role)",
    });

    // Check likes for current user
    const user = AppState.currentUser;
    let likedIds = new Set();
    if (user) {
      const likes = await dbSelect("likes", { eq: { user_id: user.id } });
      likedIds = new Set(likes.map(l => l.post_id));
    }

    feed.innerHTML = posts.length
      ? posts.map(p => renderPost({ ...p, user_liked: likedIds.has(p.id) }, { section: "inicio", showIdentity: AppState.canDo("canSeeAnonIdentity") })).join("")
      : emptyState("Aún no hay publicaciones", "Sé el primero en compartir algo");
  } catch (e) {
    feed.innerHTML = `<div class="empty-state"><p>Error al cargar el feed</p></div>`;
  }
}

async function createInicioPost() {
  const user = AppState.currentUser;
  if (!user) return;

  const textarea = document.getElementById("inicio-compose");
  const content = textarea.value.trim();
  if (!content) { showToast("Escribe algo primero", "error"); return; }

  const fileInput = document.getElementById("inicio-images");
  let images = [];
  if (fileInput.files.length) {
    try { images = await uploadImages(fileInput.files); } catch {}
  }

  const isAnon = document.getElementById("inicio-anon")?.checked && canPostAnon();

  try {
    await dbInsert("posts", {
      section: "inicio",
      user_id: user.id,
      content,
      images,
      is_anon: isAnon,
    });
    textarea.value = "";
    fileInput.value = "";
    document.getElementById("inicio-image-preview").innerHTML = "";
    showToast("Publicado", "success");
    loadInicioPage();
  } catch (e) { showToast("Error al publicar", "error"); }
}

function canPostAnon() {
  return AppState.hasPlan("n2");
}

/* ── NOTICIAS ────────────────────────────────────────────────── */
async function loadNoticiasPage() {
  const feed = document.getElementById("noticias-feed");
  if (!feed) return;

  const user = AppState.currentUser;
  const canPost = user && AppState.hasRole("encargado");
  document.getElementById("news-create-section").classList.toggle("hidden", !canPost);
  document.getElementById("btn-create-news-group").classList.toggle("hidden", !AppState.hasRole("administrador"));

  feed.innerHTML = skeletonPosts(2);

  try {
    const groups = await dbSelect("news_groups", { order: "created_at" });
    if (!groups.length) { feed.innerHTML = emptyState("Sin grupos de noticias", "Los administradores deben crear grupos primero"); return; }

    let html = "";
    for (const g of groups) {
      const posts = await dbSelect("posts", {
        eq: { section: "noticias", news_group_id: g.id },
        order: "created_at",
        limit: 1,
        select: "*, profiles(username, avatar_url, plan)",
      });
      if (!posts.length) continue;
      html += `<div class="news-group">
        <div class="news-group-header">
          <div class="news-group-dot"></div>
          <span class="news-group-name">${escHtml(g.name)}</span>
          ${canPost ? `<button class="btn btn-sm btn-primary" onclick="openNewsPostModal('${g.id}')">+ Publicar</button>` : ""}
        </div>
        ${posts.map(p => renderPost(p, { section: "noticias", showIdentity: AppState.canDo("canSeeAnonIdentity") })).join("")}
      </div>`;
    }
    feed.innerHTML = html || emptyState("Sin publicaciones recientes", "");
  } catch (e) { feed.innerHTML = `<div class="empty-state"><p>Error al cargar noticias</p></div>`; }
}

function openNewsGroupModal() {
  document.getElementById("news-group-modal").classList.add("open");
}

async function createNewsGroup() {
  const name = document.getElementById("news-group-name").value.trim();
  if (!name) return;
  try {
    await dbInsert("news_groups", { name, created_by: AppState.currentUser.id });
    document.getElementById("news-group-modal").classList.remove("open");
    document.getElementById("news-group-name").value = "";
    showToast("Grupo creado", "success");
    loadNoticiasPage();
  } catch (e) { showToast("Error", "error"); }
}

function openNewsPostModal(groupId) {
  const m = document.getElementById("news-post-modal");
  m.dataset.groupId = groupId;
  m.classList.add("open");
}

async function submitNewsPost() {
  const m = document.getElementById("news-post-modal");
  const content = document.getElementById("news-post-content").value.trim();
  if (!content) return;
  const fileInput = document.getElementById("news-post-images");
  let images = [];
  if (fileInput.files.length) images = await uploadImages(fileInput.files);
  try {
    await dbInsert("posts", {
      section: "noticias",
      news_group_id: m.dataset.groupId,
      user_id: AppState.currentUser.id,
      content, images,
    });
    m.classList.remove("open");
    document.getElementById("news-post-content").value = "";
    showToast("Publicado en noticias", "success");
    loadNoticiasPage();
  } catch (e) { showToast("Error al publicar", "error"); }
}

/* ── COMUNIDADES ─────────────────────────────────────────────── */
async function loadComunidadesPage() {
  const grid = document.getElementById("comunidades-grid");
  if (!grid) return;
  grid.innerHTML = skeletonCards(4);

  try {
    const forums = await dbSelect("forums", { order: "created_at", select: "id,name,is_anon,is_private,is_hidden,member_count,created_by" });
    // hide hidden forums (only admin/owner can see)
    const visible = forums.filter(f => !f.is_hidden || AppState.hasRole("administrador"));
    grid.innerHTML = visible.length
      ? visible.map(f => renderForumCard(f)).join("")
      : emptyState("Sin comunidades", "Crea la primera comunidad");
  } catch (e) { grid.innerHTML = "<p>Error al cargar</p>"; }
}

function renderForumCard(f) {
  return `<div class="forum-card" onclick="openForum('${f.id}')">
    ${f.is_private ? `<div class="forum-private-icon"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div>` : ""}
    <div class="forum-card-name">${escHtml(f.name)}</div>
    <div class="forum-card-meta">${f.member_count || 0} miembros</div>
    ${f.is_anon ? `<div class="forum-card-anon">ANÓNIMO</div>` : ""}
  </div>`;
}

async function openForum(forumId) {
  // Check membership for private forums
  const sb = await initSupabase();
  const { data: forum } = await sb.from("forums").select("*").eq("id", forumId).single();
  if (!forum) return;

  if (forum.is_private) {
    const user = AppState.currentUser;
    const { data: member } = await sb.from("forum_members").select("id").eq("forum_id", forumId).eq("user_id", user?.id).single().catch(() => ({ data: null }));
    if (!member) { showToast("Este foro es privado. Necesitas invitación.", "error"); return; }
  }

  // Navigate to foro detail (simplified: show in foros page)
  openForumDetail(forum);
}

function createForumModal() {
  document.getElementById("create-forum-modal").classList.add("open");
}

async function submitCreateForum() {
  const user = AppState.currentUser;
  if (!user) return;

  const name = document.getElementById("forum-name").value.trim();
  const isPrivate = document.getElementById("forum-private").checked;
  const isAnon = document.getElementById("forum-anon").checked;
  const isHidden = document.getElementById("forum-hidden")?.checked;

  if (!name) { showToast("Ponle un nombre al foro", "error"); return; }

  // Validate plan permissions for anon forums
  if (isAnon && !AppState.hasRole("propietario") && !AppState.hasPlan("n1")) {
    showToast("Necesitas Plan N1 o superior para crear foros anónimos", "error"); return;
  }
  if (isHidden && !AppState.hasPlan("n3")) {
    showToast("Solo Plan N3 puede crear foros ocultos", "error"); return;
  }

  try {
    await dbInsert("forums", {
      name, is_private: isPrivate, is_anon: isAnon, is_hidden: isHidden || false,
      created_by: user.id, member_count: 1,
    });
    // Auto-join creator
    const { data: f } = await (await initSupabase()).from("forums").select("id").eq("name", name).eq("created_by", user.id).single();
    if (f) await dbInsert("forum_members", { forum_id: f.id, user_id: user.id, role: "admin" });

    document.getElementById("create-forum-modal").classList.remove("open");
    showToast("Foro creado", "success");
    loadComunidadesPage();
    loadForosPage();
  } catch (e) { showToast("Error al crear foro", "error"); }
}

/* ── FOROS (los míos) ────────────────────────────────────────── */
async function loadForosPage() {
  const container = document.getElementById("foros-list");
  if (!container || !AppState.currentUser) return;
  container.innerHTML = skeletonCards(3);

  try {
    const sb = await initSupabase();
    const { data: memberships } = await sb.from("forum_members")
      .select("*, forums(id,name,is_anon,is_private,member_count)")
      .eq("user_id", AppState.currentUser.id);

    container.innerHTML = memberships?.length
      ? memberships.map(m => renderForumCard(m.forums)).join("")
      : emptyState("Aún no estás en ningún foro", "Explora comunidades para unirte");
  } catch (e) { container.innerHTML = "<p>Error al cargar</p>"; }
}

function openForumDetail(forum) {
  navigateTo("foros");
  const container = document.getElementById("foros-list");
  container.innerHTML = `
    <div style="margin-bottom:1rem;display:flex;align-items:center;gap:.5rem">
      <button class="btn btn-secondary btn-sm" onclick="loadForosPage()">← Mis foros</button>
      <h2 style="font-size:1rem">${escHtml(forum.name)}</h2>
      ${forum.is_anon ? '<span class="forum-card-anon">ANÓNIMO</span>' : ""}
    </div>
    <div id="forum-detail-feed">${skeletonPosts(2)}</div>
    <div class="create-post mt-md">
      <div class="create-row">
        <textarea class="create-input" id="forum-compose" placeholder="Escribe algo en este foro..." rows="2"></textarea>
      </div>
      <div class="create-actions">
        <label class="btn btn-secondary btn-sm">
          <svg style="width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
          Imagen
          <input type="file" accept="image/*" multiple style="display:none" id="forum-images">
        </label>
        <button class="btn btn-primary btn-sm" onclick="submitForumPost('${forum.id}','${forum.is_anon}')">Publicar</button>
      </div>
    </div>
  `;
  loadForumPosts(forum.id, forum.is_anon);
}

async function loadForumPosts(forumId, isAnon) {
  const feed = document.getElementById("forum-detail-feed");
  if (!feed) return;
  try {
    const posts = await dbSelect("posts", {
      eq: { section: "forum", forum_id: forumId },
      order: "created_at",
      limit: 30,
      select: "*, profiles(username, avatar_url, plan)",
    });
    feed.innerHTML = posts.length
      ? posts.map(p => renderPost(p, { section: "forum", showIdentity: AppState.canDo("canSeeAnonIdentity") })).join("")
      : emptyState("Sin publicaciones aún", "Sé el primero en publicar");
  } catch (e) { feed.innerHTML = "<p>Error</p>"; }
}

async function submitForumPost(forumId, isAnon) {
  const user = AppState.currentUser;
  const content = document.getElementById("forum-compose").value.trim();
  if (!content) return;
  const fileInput = document.getElementById("forum-images");
  let images = [];
  if (fileInput.files.length) images = await uploadImages(fileInput.files);
  try {
    await dbInsert("posts", {
      section: "forum", forum_id: forumId,
      user_id: user.id, content, images,
      is_anon: isAnon === "true" || isAnon === true,
    });
    document.getElementById("forum-compose").value = "";
    fileInput.value = "";
    showToast("Publicado", "success");
    loadForumPosts(forumId, isAnon);
  } catch (e) { showToast("Error", "error"); }
}

/* ── PERFIL ──────────────────────────────────────────────────── */
async function loadPerfilPage() {
  const user = AppState.currentUser;
  if (!user) return;

  document.getElementById("profile-username").textContent = user.username || "Usuario";
  document.getElementById("profile-bio").textContent = user.bio || "Sin biografía";
  document.getElementById("profile-role-badge").innerHTML = roleBadge(user.role);
  document.getElementById("profile-plan-badge").innerHTML = user.plan && user.plan !== "free"
    ? `<span class="plan-badge plan-${user.plan}">${user.plan.toUpperCase()}</span>` : "";

  // Banner
  const bannerEl = document.getElementById("profile-banner");
  if (user.banner_url) bannerEl.innerHTML = `<img src="${user.banner_url}" alt="">`;
  else if (user.banner_color) bannerEl.style.background = user.banner_color;

  // Avatar
  const avatarEl = document.getElementById("profile-avatar-img");
  if (user.avatar_url) avatarEl.innerHTML = `<img src="${user.avatar_url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
  else avatarEl.textContent = (user.username || "U")[0].toUpperCase();

  // Gallery
  loadProfileGallery(user.id);
  loadProfileForums(user.id);
}

async function loadProfileGallery(userId) {
  const container = document.getElementById("profile-gallery");
  if (!container) return;
  try {
    const sb = await initSupabase();
    const { data: posts } = await sb.from("posts").select("images").eq("user_id", userId).not("images", "is", null);
    const images = posts?.flatMap(p => p.images || []) || [];
    container.innerHTML = images.length
      ? images.slice(0, 9).map(src => `<img src="${src}" onclick="openLightbox('${src}')" style="width:100%;aspect-ratio:1;object-fit:cover;border-radius:var(--radius-sm);cursor:pointer">`).join("")
      : `<p style="color:var(--text-3);font-size:.82rem;grid-column:1/-1">Sin imágenes aún</p>`;
  } catch {}
}

async function loadProfileForums(userId) {
  const container = document.getElementById("profile-forums");
  if (!container) return;
  try {
    const sb = await initSupabase();
    const { data } = await sb.from("forum_members").select("forums(name)").eq("user_id", userId);
    container.innerHTML = data?.length
      ? data.map(m => `<span class="plan-badge plan-n1" style="margin:.2rem">${escHtml(m.forums?.name||"")}</span>`).join("")
      : `<p style="color:var(--text-3);font-size:.82rem">Sin foros</p>`;
  } catch {}
}

async function saveProfile() {
  const user = AppState.currentUser;
  const username = document.getElementById("edit-username").value.trim();
  const bio = document.getElementById("edit-bio").value.trim();
  const bannerColor = document.getElementById("edit-banner-color").value;

  const updates = {};
  if (username) updates.username = username;
  if (bio !== undefined) updates.bio = bio;
  updates.banner_color = bannerColor;

  // Avatar upload
  const avatarFile = document.getElementById("upload-avatar").files[0];
  if (avatarFile) {
    try { updates.avatar_url = await uploadFile("avatars", `${user.id}/avatar`, avatarFile); } catch {}
  }

  // Banner image (plan check)
  const bannerFile = document.getElementById("upload-banner")?.files[0];
  if (bannerFile && AppState.hasPlan("n1")) {
    try { updates.banner_url = await uploadFile("banners", `${user.id}/banner`, bannerFile); } catch {}
  }

  try {
    const updated = await dbUpdate("profiles", user.id, updates);
    AppState.currentUser = { ...user, ...updated };
    renderMenuAccounts();
    showToast("Perfil guardado", "success");
    document.getElementById("edit-profile-modal").classList.remove("open");
    loadPerfilPage();
  } catch (e) { showToast("Error al guardar", "error"); }
}

/* ── ADMIN PANEL ─────────────────────────────────────────────── */
async function loadAdminPage() {
  const user = AppState.currentUser;
  if (!user || !AppState.hasRole("administrador")) {
    navigateTo("inicio");
    return;
  }
  document.getElementById("owner-panel-section").classList.toggle("hidden", !AppState.hasRole("propietario"));
  loadAdminUsers();
}

async function loadAdminUsers() {
  const container = document.getElementById("admin-users-list");
  if (!container) return;
  container.innerHTML = skeletonCards(3);
  try {
    const users = await dbSelect("profiles", { order: "created_at" });
    container.innerHTML = users.map(u => `
      <div class="user-list-item">
        <div class="avatar" style="width:34px;height:34px;font-size:.8rem">${(u.username||"U")[0].toUpperCase()}</div>
        <div class="user-list-info">
          <div class="user-list-name">${escHtml(u.username||"Sin nombre")}</div>
          <div style="display:flex;gap:.3rem;flex-wrap:wrap;margin-top:.2rem">
            ${roleBadge(u.role)}
            ${u.plan && u.plan !== "free" ? `<span class="plan-badge plan-${u.plan}">${u.plan.toUpperCase()}</span>` : ""}
          </div>
        </div>
        ${canSuspend(u) ? `<button class="btn btn-danger btn-sm" onclick="suspendUser('${u.id}')">Suspender</button>` : ""}
      </div>`).join("");
  } catch (e) { container.innerHTML = "<p>Error</p>"; }
}

function canSuspend(targetUser) {
  const me = AppState.currentUser;
  if (!me) return false;
  if (me.role === "propietario") return ["usuario", "encargado", "administrador"].includes(targetUser.role) && targetUser.id !== me.id;
  if (me.role === "administrador") return ["usuario", "encargado"].includes(targetUser.role);
  return false;
}

async function suspendUser(userId) {
  const reason = prompt("Razón de la suspensión:");
  if (!reason) return;
  try {
    await dbUpdate("profiles", userId, { suspended: true, suspend_reason: reason });
    showToast("Usuario suspendido", "success");
    loadAdminUsers();
  } catch (e) { showToast("Error", "error"); }
}

async function createUserFromPanel() {
  if (!AppState.hasRole("propietario")) return;
  const email = document.getElementById("new-user-email").value.trim();
  const password = document.getElementById("new-user-password").value;
  const username = document.getElementById("new-user-username").value.trim();
  const role = document.getElementById("new-user-role").value;
  if (!email || !password || !username) { showToast("Completa todos los campos", "error"); return; }
  try {
    const { data } = await signUp(email, password, username);
    if (data?.user) await dbUpdate("profiles", data.user.id, { role });
    showToast("Usuario creado", "success");
    loadAdminUsers();
  } catch (e) { showToast(e.message || "Error", "error"); }
}

async function setUserPlan(userId, plan) {
  if (!AppState.hasRole("propietario")) return;
  const days = CONFIG[`PLAN_${plan.toUpperCase()}_DAYS`] || 30;
  const expires = new Date(Date.now() + days * 86400000).toISOString();
  try {
    await dbUpdate("profiles", userId, { plan, plan_expires: expires });
    showToast(`Plan ${plan.toUpperCase()} asignado`, "success");
    loadAdminUsers();
  } catch (e) { showToast("Error", "error"); }
}

/* ── PLANES ──────────────────────────────────────────────────── */
async function loadPlanesPage() {
  // Data is static (rendered in HTML), just mark current plan
  const user = AppState.currentUser;
  if (!user) return;
  document.querySelectorAll(".plan-card").forEach(c => {
    c.style.borderColor = c.dataset.plan === user.plan ? "var(--accent)" : "";
  });
}

/* ── HELPERS ─────────────────────────────────────────────────── */
function skeletonPosts(n) {
  return Array(n).fill(`
    <div class="card post-card">
      <div style="display:flex;gap:.65rem;margin-bottom:.75rem">
        <div class="skeleton" style="width:38px;height:38px;border-radius:50%;flex-shrink:0"></div>
        <div style="flex:1"><div class="skeleton" style="height:14px;width:60%;margin-bottom:.4rem"></div><div class="skeleton" style="height:10px;width:35%"></div></div>
      </div>
      <div class="skeleton" style="height:14px;width:90%;margin-bottom:.35rem"></div>
      <div class="skeleton" style="height:14px;width:75%"></div>
    </div>`).join("");
}

function skeletonCards(n) {
  return `<div class="forum-grid">${Array(n).fill('<div class="forum-card"><div class="skeleton" style="height:14px;width:70%;margin-bottom:.4rem"></div><div class="skeleton" style="height:10px;width:45%"></div></div>').join("")}</div>`;
}

function emptyState(title, desc) {
  return `<div class="empty-state">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M8 12h8M12 8v8"/></svg>
    <h3>${title}</h3>${desc ? `<p>${desc}</p>` : ""}
  </div>`;
}

function roleBadge(role) {
  const map = { encargado: "Encargado", administrador: "Admin", propietario: "Propietario" };
  if (!map[role]) return "";
  return `<span class="role-badge role-${role}">${map[role]}</span>`;
}

// Admin tab switching
document.querySelectorAll(".admin-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".admin-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".admin-panel-section").forEach(s => s.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(tab.dataset.tab)?.classList.add("active");
  });
});

// Image preview for inicio
document.getElementById("inicio-images")?.addEventListener("change", function() {
  const preview = document.getElementById("inicio-image-preview");
  preview.innerHTML = Array.from(this.files).slice(0,4).map(f => {
    const url = URL.createObjectURL(f);
    return `<img src="${url}" style="height:60px;border-radius:6px;object-fit:cover">`;
  }).join("");
});