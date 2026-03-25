// ============================================================
//  RedCW — App Core (router, UI helpers, theme)
// ============================================================

/* ── Theme ─────────────────────────────────────────────────── */
function applyTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  localStorage.setItem("rcw_theme", t);
  AppState.theme = t;
  const track = document.querySelector(".toggle-track");
  if (track) track.classList.toggle("on", t === "light");
}
applyTheme(AppState.theme);

/* ── Router ────────────────────────────────────────────────── */
const PAGES = ["inicio", "noticias", "comunidades", "foros", "perfil", "admin", "login", "register", "planes"];

function navigateTo(pageId, opts = {}) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  const target = document.getElementById(`page-${pageId}`);
  if (target) {
    target.classList.add("active");
    target.scrollTop = 0;
  }

  // Update nav icons
  document.querySelectorAll(".nav-item").forEach(n => {
    n.classList.toggle("active", n.dataset.page === pageId);
  });

  // Show/hide header and nav
  const noLayout = ["login", "register"].includes(pageId);
  document.getElementById("app-header").style.display = noLayout ? "none" : "";
  document.getElementById("app-nav").style.display = noLayout ? "none" : "";
  document.body.style.paddingTop = noLayout ? "0" : "";
  document.body.style.paddingBottom = noLayout ? "0" : "";

  window.history.pushState({ page: pageId }, "", `#${pageId}`);
  if (opts.onEnter) opts.onEnter();

  // Lazy load page data
  const loaders = {
    inicio: loadInicioPage,
    noticias: loadNoticiasPage,
    comunidades: loadComunidadesPage,
    foros: loadForosPage,
    perfil: loadPerfilPage,
    admin: loadAdminPage,
    planes: loadPlanesPage,
  };
  if (loaders[pageId]) loaders[pageId]();
}

window.addEventListener("popstate", (e) => {
  const page = e.state?.page || "inicio";
  navigateTo(page);
});

/* ── Toasts ─────────────────────────────────────────────────── */
function showToast(msg, type = "info", duration = 3000) {
  const c = document.getElementById("toast-container");
  const t = document.createElement("div");
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => {
    t.style.animation = "none";
    t.style.opacity = "0";
    t.style.transform = "translateY(6px) scale(.95)";
    t.style.transition = ".25s ease";
    setTimeout(() => t.remove(), 280);
  }, duration);
}

/* ── Lightbox ───────────────────────────────────────────────── */
function openLightbox(src) {
  const lb = document.getElementById("lightbox");
  lb.querySelector("img").src = src;
  lb.classList.add("open");
}
document.getElementById("lightbox")?.addEventListener("click", () => {
  document.getElementById("lightbox").classList.remove("open");
});

/* ── Drawer (hamburger menu) ────────────────────────────────── */
const menuDrawer = document.getElementById("menu-drawer");

function openMenu() {
  const overlay = menuDrawer.closest(".drawer-overlay");
  overlay.classList.add("open");
  renderMenuAccounts();
}

function closeMenu() {
  menuDrawer.closest(".drawer-overlay").classList.remove("open");
}

function renderMenuAccounts() {
  const user = AppState.currentUser;
  if (!user) return;

  // Session chip in header
  const chip = document.querySelector(".session-chip .chip-name");
  const chipAv = document.querySelector(".session-chip .avatar-xs");
  if (chip) chip.textContent = user.username || "Usuario";
  if (chipAv) {
    if (user.avatar_url) {
      chipAv.innerHTML = `<img src="${user.avatar_url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`;
    } else {
      chipAv.textContent = (user.username || "U")[0].toUpperCase();
    }
  }

  // Plan badge in menu
  const planEl = document.getElementById("menu-plan-info");
  if (planEl) {
    const p = user.plan || "free";
    planEl.innerHTML = p !== "free"
      ? `<span class="plan-badge plan-${p}">${p.toUpperCase()}</span>`
      : "";
  }
}

// Theme toggle in drawer
document.getElementById("theme-toggle-track")?.addEventListener("click", () => {
  const newTheme = AppState.theme === "dark" ? "light" : "dark";
  applyTheme(newTheme);
  document.getElementById("theme-toggle-track").classList.toggle("on", newTheme === "light");
});

// Close on overlay click
document.querySelector(".drawer-overlay")?.addEventListener("click", (e) => {
  if (e.target === e.currentTarget) closeMenu();
});

/* ── Nav items ──────────────────────────────────────────────── */
document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    const page = item.dataset.page;
    if (!AppState.currentUser && !["login", "register"].includes(page)) {
      showToast("Inicia sesión para continuar", "error");
      navigateTo("login");
      return;
    }
    navigateTo(page);
  });
});

/* ── Session chip → perfil ──────────────────────────────────── */
document.querySelector(".session-chip")?.addEventListener("click", () => {
  navigateTo("perfil");
});

/* ── Helpers de posts ────────────────────────────────────────── */
function renderPost(post, opts = {}) {
  const user = AppState.currentUser;
  const isAnon = post.is_anon && !opts.showIdentity;
  const authorName = isAnon ? "Anónimo" : (post.profiles?.username || "Usuario");
  const authorAvatar = isAnon ? null : post.profiles?.avatar_url;
  const nameClass = planNameClass(post.profiles?.plan);
  const initials = authorName[0].toUpperCase();

  let imagesHtml = "";
  if (post.images?.length) {
    const count = Math.min(post.images.length, 4);
    imagesHtml = `<div class="post-images count-${count}">
      ${post.images.slice(0, count).map((src, i) =>
        `<img src="${src}" class="img-${i}" loading="lazy" alt="" onclick="openLightbox('${src}')">`
      ).join("")}
    </div>`;
  }

  const canDelete = user && (user.id === post.user_id || user.role === "administrador" || user.role === "propietario");

  return `
  <div class="card post-card" data-post-id="${post.id}">
    <div class="post-header">
      <div class="avatar">
        ${authorAvatar ? `<img src="${authorAvatar}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : initials}
      </div>
      <div class="post-meta">
        <div class="post-author ${nameClass}">${escHtml(authorName)}</div>
        <div class="post-time">${timeAgo(post.created_at)}</div>
      </div>
      ${canDelete ? `<button class="btn-icon" onclick="deletePost('${post.id}','${opts.section || 'inicio'}')">
        <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/></svg>
      </button>` : ""}
    </div>
    <div class="post-body">${escHtml(post.content)}</div>
    ${imagesHtml}
    <div class="post-actions">
      <button class="btn-action ${post.user_liked ? 'liked' : ''}" onclick="toggleLike('${post.id}','${opts.section || 'inicio'}')">
        <svg viewBox="0 0 24 24"><path d="M20.8 4.6a5.5 5.5 0 00-7.8 0L12 5.6l-1-1a5.5 5.5 0 00-7.8 7.8l1 1L12 21l7.8-7.8 1-1a5.5 5.5 0 000-7.8z"/></svg>
        <span>${post.likes_count || 0}</span>
      </button>
      <button class="btn-action" onclick="openComments('${post.id}','${opts.section || 'inicio'}')">
        <svg viewBox="0 0 24 24"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
        <span>${post.comments_count || 0}</span>
      </button>
    </div>
  </div>`;
}

function planNameClass(plan) {
  if (plan === "n1") return "color-n1";
  if (plan === "n2") return "color-n2";
  if (plan === "n3") return "color-n3";
  return "";
}

function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function timeAgo(dateStr) {
  if (!dateStr) return "";
  const diff = Date.now() - new Date(dateStr);
  const s = Math.floor(diff / 1000);
  if (s < 60) return "ahora";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d`;
  return new Date(dateStr).toLocaleDateString("es", { day: "2-digit", month: "short" });
}

/* ── Like / Delete (stub — conectar con Supabase) ─────────────── */
async function toggleLike(postId, section) {
  if (!AppState.currentUser) { showToast("Inicia sesión", "error"); return; }
  try {
    const sb = await initSupabase();
    const uid = AppState.currentUser.id;
    const { data: existing } = await sb.from("likes").select("id").eq("post_id", postId).eq("user_id", uid).single().catch(() => ({ data: null }));
    if (existing) {
      await sb.from("likes").delete().eq("post_id", postId).eq("user_id", uid);
    } else {
      await sb.from("likes").insert({ post_id: postId, user_id: uid });
    }
    // Re-render (simplified)
    const loaders = { inicio: loadInicioPage, noticias: loadNoticiasPage };
    if (loaders[section]) loaders[section]();
  } catch (e) { showToast("Error al reaccionar", "error"); }
}

async function deletePost(postId, section) {
  if (!confirm("¿Eliminar esta publicación?")) return;
  try {
    await dbDelete("posts", postId);
    showToast("Publicación eliminada", "success");
    const loaders = { inicio: loadInicioPage, noticias: loadNoticiasPage };
    if (loaders[section]) loaders[section]();
  } catch (e) { showToast("Error al eliminar", "error"); }
}

function openComments(postId, section) {
  // Abre modal de comentarios
  const modal = document.getElementById("comments-modal");
  modal.dataset.postId = postId;
  modal.dataset.section = section;
  modal.classList.add("open");
  loadComments(postId);
}

async function loadComments(postId) {
  const container = document.getElementById("comments-list");
  container.innerHTML = `<div class="skeleton" style="height:60px;margin-bottom:.5rem"></div>`.repeat(2);
  try {
    const comments = await dbSelect("comments", { eq: { post_id: postId }, order: "created_at", asc: true, select: "*, profiles(username,avatar_url,plan)" });
    container.innerHTML = comments.length
      ? comments.map(c => `
        <div style="display:flex;gap:.6rem;margin-bottom:.75rem">
          <div class="avatar" style="width:30px;height:30px;font-size:.7rem;flex-shrink:0">
            ${c.profiles?.avatar_url ? `<img src="${c.profiles.avatar_url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : (c.profiles?.username||"U")[0].toUpperCase()}
          </div>
          <div style="flex:1">
            <div style="font-size:.8rem;font-weight:600;color:var(--text)" class="${planNameClass(c.profiles?.plan)}">${escHtml(c.profiles?.username||"Usuario")}</div>
            <div style="font-size:.85rem;color:var(--text)">${escHtml(c.content)}</div>
            <div style="font-size:.7rem;color:var(--text-3)">${timeAgo(c.created_at)}</div>
          </div>
        </div>`).join("")
      : `<div class="empty-state" style="padding:1.5rem">
          <p>Sin comentarios aún</p>
        </div>`;
  } catch (e) { container.innerHTML = "<p>Error al cargar</p>"; }
}

async function submitComment() {
  const modal = document.getElementById("comments-modal");
  const input = document.getElementById("comment-input");
  const text = input.value.trim();
  if (!text || !AppState.currentUser) return;
  try {
    await dbInsert("comments", { post_id: modal.dataset.postId, user_id: AppState.currentUser.id, content: text });
    input.value = "";
    await loadComments(modal.dataset.postId);
    showToast("Comentario añadido", "success");
  } catch (e) { showToast("Error al comentar", "error"); }
}

/* ── Image upload helper ───────────────────────────────────── */
async function uploadImages(files, bucket = "posts") {
  const urls = [];
  for (const file of Array.from(files).slice(0, 4)) {
    if (file.size > CONFIG.MAX_IMAGE_SIZE_MB * 1024 * 1024) {
      showToast(`Imagen demasiado grande (máx ${CONFIG.MAX_IMAGE_SIZE_MB}MB)`, "error");
      continue;
    }
    const path = `${AppState.currentUser.id}/${Date.now()}_${file.name}`;
    const url = await uploadFile(bucket, path, file);
    urls.push(url);
  }
  return urls;
}

/* ── Init ──────────────────────────────────────────────────── */
async function initApp() {
  await initSupabase();
  const session = await getCurrentSession();
  const hash = window.location.hash.replace("#", "") || "inicio";

  if (!session) {
    navigateTo("login");
  } else {
    renderMenuAccounts();
    navigateTo(PAGES.includes(hash) ? hash : "inicio");
  }

  // Listen for auth changes
  const sb = await initSupabase();
  sb.auth.onAuthStateChange(async (event, session) => {
    if (event === "SIGNED_IN" && session) {
      await loadUserProfile(session.user.id);
      renderMenuAccounts();
    } else if (event === "SIGNED_OUT") {
      navigateTo("login");
    }
  });
}

document.addEventListener("DOMContentLoaded", initApp);