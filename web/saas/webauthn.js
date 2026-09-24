/**
 * Passkey (WebAuthn) helpers. The server sends standard JSON options; this
 * module converts them to/from the ArrayBuffers navigator.credentials needs.
 * Nothing here touches vault keys: passkeys gate the cloud session only.
 */

export function supported() {
  return Boolean(globalThis.PublicKeyCredential && globalThis.navigator && navigator.credentials);
}

export function b64uToBytes(value) {
  const b64 = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64u(buf) {
  const arr = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < arr.length; i += 1) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function descriptors(list) {
  return (list || []).map(function (item) {
    return Object.assign({}, item, { id: b64uToBytes(item.id) });
  });
}

export function creationOptions(json) {
  return Object.assign({}, json, {
    challenge: b64uToBytes(json.challenge),
    user: Object.assign({}, json.user, { id: b64uToBytes(json.user.id) }),
    excludeCredentials: descriptors(json.excludeCredentials)
  });
}

export function requestOptions(json) {
  return Object.assign({}, json, {
    challenge: b64uToBytes(json.challenge),
    allowCredentials: descriptors(json.allowCredentials)
  });
}

function base(cred) {
  return {
    id: cred.id,
    rawId: bytesToB64u(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
  };
}

export function serializeAttestation(cred) {
  const r = cred.response;
  return Object.assign(base(cred), {
    response: {
      clientDataJSON: bytesToB64u(r.clientDataJSON),
      attestationObject: bytesToB64u(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : []
    }
  });
}

export function serializeAssertion(cred) {
  const r = cred.response;
  return Object.assign(base(cred), {
    response: {
      clientDataJSON: bytesToB64u(r.clientDataJSON),
      authenticatorData: bytesToB64u(r.authenticatorData),
      signature: bytesToB64u(r.signature),
      userHandle: r.userHandle ? bytesToB64u(r.userHandle) : null
    }
  });
}

export async function createPasskey(publicKeyJson) {
  const cred = await navigator.credentials.create({ publicKey: creationOptions(publicKeyJson) });
  return serializeAttestation(cred);
}

export async function getPasskey(publicKeyJson) {
  const cred = await navigator.credentials.get({ publicKey: requestOptions(publicKeyJson) });
  return serializeAssertion(cred);
}
