// ============================================================
//  RedCW — Supabase Client & Auth
// ============================================================

// Carga dinámica del SDK de Supabase
let supabase = null;

async function initSupabase() {
  if (supabase) return supabase;
  const { createClient } = await import("https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm");
  supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_ANON_KEY);
  return supabase;
}

// ── Estado de sesión global ──────────────────────────────────
const AppState = {
  currentUser: null, // perfil completo desde DB
  session: null, // sesión de Supabase
  accounts: [], // cuentas guardadas localmente
  theme: localStorage.getItem("rcw_theme") || "dark",
  
  setUser(profile, session) {
    this.currentUser = profile;
    this.session = session;
    document.dispatchEvent(new CustomEvent("rcw:userchange", { detail: profile }));
  },
  
  clearUser() {
    this.currentUser = null;
    this.session = null;
    document.dispatchEvent(new CustomEvent("rcw:userchange", { detail: null }));
  },
  
  hasRole(role) {
    if (!this.currentUser) return false;
    const order = ["usuario", "encargado", "administrador", "propietario"];
    return order.indexOf(this.currentUser.role) >= order.indexOf(role);
  },
  
  hasPlan(plan) {
    if (!this.currentUser) return false;
    const order = ["free", "n1", "n2", "n3"];
    return order.indexOf(this.currentUser.plan || "free") >= order.indexOf(plan);
  },
  
  canDo(permission) {
    if (!this.currentUser) return false;
    return PERMISSIONS[permission]?.includes(this.currentUser.role) ?? false;
  },
};

// ── Auth helpers ─────────────────────────────────────────────
async function signIn(email, password) {
  const sb = await initSupabase();
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw error;
  await loadUserProfile(data.user.id);
  saveAccountLocally(email);
  return data;
}

async function signUp(email, password, username) {
  const sb = await initSupabase();
  const { data, error } = await sb.auth.signUp({ email, password, options: { data: { username } } });
  if (error) throw error;
  return data;
}

async function signOut() {
  const sb = await initSupabase();
  await sb.auth.signOut();
  AppState.clearUser();
  navigateTo("login");
}

async function loadUserProfile(userId) {
  const sb = await initSupabase();
  const { data } = await sb.from("profiles").select("*").eq("id", userId).single();
  const { data: { session } } = await sb.auth.getSession();
  if (data) AppState.setUser(data, session);
  return data;
}

async function getCurrentSession() {
  const sb = await initSupabase();
  const { data: { session } } = await sb.auth.getSession();
  if (session) {
    await loadUserProfile(session.user.id);
  }
  return session;
}

// ── Cuentas múltiples (localStorage) ───────────────────────
function saveAccountLocally(email) {
  let accounts = JSON.parse(localStorage.getItem("rcw_accounts") || "[]");
  if (!accounts.includes(email)) accounts.push(email);
  localStorage.setItem("rcw_accounts", JSON.stringify(accounts));
}

function getSavedAccounts() {
  return JSON.parse(localStorage.getItem("rcw_accounts") || "[]");
}

// ── DB helpers genéricos ─────────────────────────────────────
async function dbSelect(table, query = {}) {
  const sb = await initSupabase();
  let q = sb.from(table).select(query.select || "*");
  if (query.eq) Object.entries(query.eq).forEach(([k, v]) => (q = q.eq(k, v)));
  if (query.order) q = q.order(query.order, { ascending: query.asc ?? false });
  if (query.limit) q = q.limit(query.limit);
  const { data, error } = await q;
  if (error) throw error;
  return data;
}

async function dbInsert(table, payload) {
  const sb = await initSupabase();
  const { data, error } = await sb.from(table).insert(payload).select().single();
  if (error) throw error;
  return data;
}

async function dbUpdate(table, id, payload) {
  const sb = await initSupabase();
  const { data, error } = await sb.from(table).update(payload).eq("id", id).select().single();
  if (error) throw error;
  return data;
}

async function dbDelete(table, id) {
  const sb = await initSupabase();
  const { error } = await sb.from(table).delete().eq("id", id);
  if (error) throw error;
}

async function uploadFile(bucket, path, file) {
  const sb = await initSupabase();
  const { error } = await sb.storage.from(bucket).upload(path, file, { upsert: true });
  if (error) throw error;
  const { data } = sb.storage.from(bucket).getPublicUrl(path);
  return data.publicUrl;
}