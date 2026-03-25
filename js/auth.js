// ============================================================
//  RedCW — Auth Logic
// ============================================================

async function handleLogin(e) {
  if (e) e.preventDefault();
  const email = document.getElementById("login-email").value.trim();
  const password = document.getElementById("login-password").value;
  const btn = document.getElementById("btn-login");
  
  if (!email || !password) { showToast("Completa todos los campos", "error"); return; }
  
  btn.disabled = true;
  btn.textContent = "Entrando…";
  try {
    await signIn(email, password);
    navigateTo("inicio");
    showToast("¡Bienvenido!", "success");
  } catch (e) {
    showToast(e.message || "Credenciales incorrectas", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Entrar";
  }
}

async function handleRegister(e) {
  if (e) e.preventDefault();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  const username = document.getElementById("reg-username").value.trim();
  const btn = document.getElementById("btn-register");
  
  if (!email || !password || !username) { showToast("Completa todos los campos", "error"); return; }
  if (password.length < 6) { showToast("La contraseña debe tener al menos 6 caracteres", "error"); return; }
  
  btn.disabled = true;
  btn.textContent = "Creando cuenta…";
  try {
    await signUp(email, password, username);
    showToast("Cuenta creada. Revisa tu correo para confirmar.", "success");
    showAuthTab("login");
  } catch (e) {
    showToast(e.message || "Error al registrarse", "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Crear cuenta";
  }
}

function showAuthTab(tab) {
  document.getElementById("login-form").classList.toggle("hidden", tab !== "login");
  document.getElementById("register-form").classList.toggle("hidden", tab !== "register");
  document.querySelectorAll(".auth-tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
}

// Multi-account: switch
async function switchAccount(email) {
  closeMenu();
  const password = prompt(`Contraseña para ${email}:`);
  if (!password) return;
  try {
    await signOut();
    await signIn(email, password);
    navigateTo("inicio");
    showToast(`Sesión iniciada como ${email}`, "success");
  } catch (e) { showToast("Error al cambiar cuenta", "error"); }
}

function renderSavedAccounts() {
  const accounts = getSavedAccounts();
  const container = document.getElementById("saved-accounts-list");
  if (!container) return;
  container.innerHTML = accounts.map(email => `
    <div class="menu-item" onclick="switchAccount('${email}')">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
      <span>${email}</span>
    </div>`).join("") || `<div style="font-size:.8rem;color:var(--text-3);padding:.4rem .5rem">No hay cuentas guardadas</div>`;
}

document.addEventListener("rcw:userchange", renderSavedAccounts);

// Login form events
document.getElementById("login-form")?.addEventListener("submit", handleLogin);
document.getElementById("register-form")?.addEventListener("submit", handleRegister);
document.querySelectorAll(".auth-tab-btn").forEach(b => b.addEventListener("click", () => showAuthTab(b.dataset.tab)));