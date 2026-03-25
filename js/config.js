// ============================================================
//  RedCW — Configuración Global
//  Edita este archivo con tus credenciales antes de desplegar
// ============================================================

const CONFIG = {
  // --- Supabase ---
  SUPABASE_URL: "https://klitblfegdxdvitgolph.supabase.co",
  SUPABASE_ANON_KEY: "sb_publishable_JO4qZK7sBVP4Rv7_Gi3cbQ_6x6Zl1oz",

  // --- App ---
  APP_NAME: "RedCW",
  APP_VERSION: "1.0.0",
  APP_URL: "https://redcw.vercel.app",

  // --- Correos de soporte ---
  SUPPORT_EMAIL: "geraldacunacorro@gmail.com",
  ABUSE_EMAIL: "geraldacunacorro@gmail.com",
  ADMIN_EMAIL: "geraldacunacorro@gmail.com",

  // --- Planes (duración en días) ---
  PLAN_N1_DAYS: 30,
  PLAN_N2_DAYS: 30,
  PLAN_N3_DAYS: 30,

  // --- Límites de carga ---
  MAX_IMAGE_SIZE_MB: 5,
  MAX_IMAGES_PER_POST: 4,
  MAX_BANNER_SIZE_MB: 3,

  // --- Foros por cuenta según plan ---
  FORUMS_FREE_NORMAL: 1,
  FORUMS_FREE_ANON: 0,
  FORUMS_N1_NORMAL: 1,
  FORUMS_N1_ANON: 1,
  FORUMS_N2_NORMAL: 2,
  FORUMS_N2_ANON: 2,
  FORUMS_N3_NORMAL: 2,
  FORUMS_N3_ANON: 2,

  // --- Feature flags ---
  PLANS_ENABLED: true,
  ANONYMOUS_POSTS_ENABLED: true,
  PWA_ENABLED: true,
};

// Roles
const ROLES = {
  USUARIO: "usuario",
  ENCARGADO: "encargado",
  ADMINISTRADOR: "administrador",
  PROPIETARIO: "propietario",
};

// Planes
const PLANS = {
  FREE: "free",
  N1: "n1",
  N2: "n2",
  N3: "n3",
};

// Permisos por rol
const PERMISSIONS = {
  canPostInicio: [ROLES.USUARIO, ROLES.ENCARGADO, ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canPostNoticias: [ROLES.ENCARGADO, ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canCreateNewsGroup: [ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canSeeAnonIdentity: [ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canSuspendUsers: [ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canAccessAdminPanel: [ROLES.ADMINISTRADOR, ROLES.PROPIETARIO],
  canAccessOwnerPanel: [ROLES.PROPIETARIO],
  canCreateAnonForum: [ROLES.PROPIETARIO], // gratis para propietario; planes N1-N3 también
  canManagePlans: [ROLES.PROPIETARIO],
};

// Permisos de planes
const PLAN_PERMS = {
  [PLANS.N1]: {
    anonForum: 1,
    normalForum: 1,
    bannerImage: true,
    colorName: true,
    anonymousPost: false,
    hiddenForum: false,
  },
  [PLANS.N2]: {
    anonForum: 2,
    normalForum: 3,
    bannerImage: true,
    colorName: true,
    anonymousPost: true,
    hiddenForum: false,
  },
  [PLANS.N3]: {
    anonForum: 2,
    normalForum: 2,
    bannerImage: true,
    colorName: true,
    colorPost: true,
    anonymousPost: true,
    hiddenForum: true,
  },
};
