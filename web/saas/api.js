/** Same-origin API client. Sends authKey, never vaultKey or the master password. */

const JSON_HEADERS = { "Content-Type": "application/json", Accept: "application/json" };

export class ApiError extends Error {
  constructor(status, payload) {
    super((payload && payload.message) || "Request failed");
    this.status = status;
    this.payload = payload || {};
    this.code = this.payload.error || "http_error";
  }
}

async function request(method, path, body) {
  const opts = {
    method: method,
    credentials: "same-origin",
    headers: body === undefined ? { Accept: "application/json" } : JSON_HEADERS
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, opts);
  } catch (err) {
    const error = new ApiError(0, {
      error: "network",
      message: "Could not reach the pwmanager API. You can still use a local vault on this device."
    });
    throw error;
  }
  const text = await response.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (err) {
      payload = { message: text.slice(0, 200) };
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, payload);
  }
  return payload;
}

export async function health() {
  return request("GET", "/api/health");
}

export async function prelogin(email) {
  return request("POST", "/api/prelogin", { email: email });
}

export async function register(email, authKeyB64, kdfSaltB64, kdfParams) {
  return request("POST", "/api/register", {
    email: email,
    auth_key: authKeyB64,
    kdf_salt: kdfSaltB64,
    kdf_params: kdfParams
  });
}

export async function login(email, authKeyB64) {
  return request("POST", "/api/login", { email: email, auth_key: authKeyB64 });
}

export async function loginSalt(email) {
  return request("POST", "/api/login", { email: email });
}

export async function logout() {
  try {
    return await request("POST", "/api/logout", {});
  } catch (err) {
    return { ok: false };
  }
}

export async function me() {
  return request("GET", "/api/me");
}

export async function putVault(envelope) {
  return request("PUT", "/api/vault", envelope);
}

export async function getVault() {
  return request("GET", "/api/vault");
}

export async function vaultRevisions() {
  return request("GET", "/api/vault/revisions");
}

export async function checkout(interval) {
  return request("POST", "/api/checkout", { interval: interval });
}

export async function deleteAccount(authKeyB64) {
  // The server re-checks the auth key: a session cookie alone cannot delete.
  return request("POST", "/api/account/delete", { confirm: "DELETE", auth_key: authKeyB64 });
}

export async function exportAccount() {
  return request("GET", "/api/account/export");
}
