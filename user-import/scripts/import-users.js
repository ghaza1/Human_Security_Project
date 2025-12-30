import fs from "fs";
import path from "path";
import xlsx from "xlsx";
import { fileURLToPath } from "url";
import fetch from "node-fetch";

// Make script directory available in ESM (so paths work no matter where you run the command)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ======================
// CONFIG
// ======================
const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || "http://localhost:8081";
const REALM = process.env.KEYCLOAK_REALM || "secured-library";

const ADMIN_CLIENT_ID = process.env.KEYCLOAK_ADMIN_CLIENT_ID || "admin-cli";
const ADMIN_USERNAME = process.env.KEYCLOAK_ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD || "admin";

// Excel file must be located next to this script inside /scripts
const EXCEL_FILE = "Humans_Excel.xlsx";

// Default role if Excel doesn't provide one
const DEFAULT_ROLE = "read_only";

// ======================
// HELPERS
// ======================
async function getAdminToken() {
  const url = `${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token`;

  const body = new URLSearchParams();
  body.set("grant_type", "password");
  body.set("client_id", ADMIN_CLIENT_ID);
  body.set("username", ADMIN_USERNAME);
  body.set("password", ADMIN_PASSWORD);

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Failed to get admin token: HTTP ${res.status} ${JSON.stringify(data)}`);
  }
  return data.access_token;
}

async function keycloakRequest(token, method, endpoint, body) {
  const url = `${KEYCLOAK_BASE_URL}/admin/realms/${REALM}${endpoint}`;
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: body ? JSON.stringify(body) : undefined
  });

  // 204 No Content
  if (res.status === 204) return { ok: true, status: 204, data: null };

  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }

  return { ok: res.ok, status: res.status, data };
}

async function ensureUser(token, user) {
  // Check if user already exists
  const q = encodeURIComponent(user.username);
  const found = await keycloakRequest(token, "GET", `/users?username=${q}`, null);

  if (found.ok && Array.isArray(found.data) && found.data.length > 0) {
    return { created: false, id: found.data[0].id };
  }

  // Create user
  const payload = {
    username: user.username,
    enabled: true,
    email: user.email || "",
    firstName: user.firstName || "",
    lastName: user.lastName || "",
    credentials: [
      {
        type: "password",
        value: user.password,
        temporary: false
      }
    ]
  };

  const created = await keycloakRequest(token, "POST", "/users", payload);
  if (!created.ok) {
    throw new Error(`Create user failed (${user.username}): HTTP ${created.status} ${JSON.stringify(created.data)}`);
  }

  // fetch user id after creation
  const after = await keycloakRequest(token, "GET", `/users?username=${q}`, null);
  if (!after.ok || !Array.isArray(after.data) || after.data.length === 0) {
    throw new Error(`User created but cannot retrieve id: ${user.username}`);
  }

  return { created: true, id: after.data[0].id };
}

async function getRealmRole(token, roleName) {
  const res = await keycloakRequest(token, "GET", `/roles/${encodeURIComponent(roleName)}`, null);
  if (!res.ok) return null;
  return res.data;
}

async function ensureRoleExists(token, roleName) {
  const role = await getRealmRole(token, roleName);
  if (role) return role;

  const created = await keycloakRequest(token, "POST", `/roles`, { name: roleName });
  if (!created.ok) {
    throw new Error(`Failed to create role "${roleName}": HTTP ${created.status} ${JSON.stringify(created.data)}`);
  }

  const again = await getRealmRole(token, roleName);
  if (!again) {
    throw new Error(`Role "${roleName}" created but cannot retrieve it`);
  }
  return again;
}

async function assignRealmRoleToUser(token, userId, roleName) {
  const role = await ensureRoleExists(token, roleName);

  const res = await keycloakRequest(token, "POST", `/users/${userId}/role-mappings/realm`, [role]);
  if (!res.ok) {
    throw new Error(`Assign role failed (userId=${userId}, role=${roleName}): HTTP ${res.status} ${JSON.stringify(res.data)}`);
  }
}

function readExcelUsers() {
  // Look for the Excel file next to the script (scripts/), then fallback to current working dir
  const candidates = [
    path.resolve(__dirname, EXCEL_FILE),
    path.resolve(process.cwd(), EXCEL_FILE),
  ];
  const filePath = candidates.find((p) => fs.existsSync(p));

  if (!filePath) {
    throw new Error(
      `Excel not found. Looked in:\n${candidates.map(p => " - " + p).join("\n")}\n✅ حط Humans_Excel.xlsx جنب import-users.js جوّا scripts (أو شغّل الأمر من جوّا scripts).`
    );
  }

  const wb = xlsx.readFile(filePath);
  const sheetName = wb.SheetNames[0];
  const ws = wb.Sheets[sheetName];

  const rows = xlsx.utils.sheet_to_json(ws, { defval: "" });

  // Expected columns (flexible):
  // username | password | email | firstName | lastName | role
  const users = rows.map((r) => ({
    username: String(r.username || r.Username || r.USERNAME || "").trim(),
    password: String(r.password || r.Password || r.PASSWORD || "P@ssw0rd!").trim(),
    email: String(r.email || r.Email || r.EMAIL || "").trim(),
    firstName: String(r.firstName || r.FirstName || r.firstname || "").trim(),
    lastName: String(r.lastName || r.LastName || r.lastname || "").trim(),
    role: String(r.role || r.Role || r.ROLE || DEFAULT_ROLE).trim() || DEFAULT_ROLE
  }))
  .filter(u => u.username);

  return users;
}

// ======================
// MAIN
// ======================
async function main() {
  try {
    const users = readExcelUsers();
    if (users.length === 0) {
      console.log("⚠️ No users found in Excel.");
      return;
    }

    console.log(`📄 Loaded ${users.length} users from Excel.`);
    const token = await getAdminToken();
    console.log("🔑 Admin token acquired.");

    let createdCount = 0;
    let existedCount = 0;

    for (const u of users) {
      const { created, id } = await ensureUser(token, u);
      if (created) {
        createdCount++;
        console.log(`✅ Created: ${u.username}`);
      } else {
        existedCount++;
        console.log(`ℹ️ Exists: ${u.username}`);
      }

      // Assign role
      const roleName = u.role || DEFAULT_ROLE;
      await assignRealmRoleToUser(token, id, roleName);
      console.log(`🎭 Role assigned: ${u.username} -> ${roleName}`);
    }

    console.log("=======================================");
    console.log(`✅ Done. Created: ${createdCount}, Already existed: ${existedCount}`);
    console.log("=======================================");

  } catch (e) {
    console.error("❌ Fatal:", e.message || e);
    process.exit(1);
  }
}

main();
