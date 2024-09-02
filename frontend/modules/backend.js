import { base64Decode } from "./bytes.js";

const backendURL = "http://localhost:5418";

// Fetches the public key for a given `dayjs` date and time from the backend.
export async function getPublicKey(datetime) {
  const resp = await fetch(
    backendURL + "/v0/get_public_key?time=" + datetime.unix()
  );
  if (resp.status != 200) {
    throw new Error(resp.statusText + ": " + (await resp.text()));
  }

  let ret = await resp.json();
  ret.spki = base64Decode(ret.spki);
  return ret;
}

// Fetches the private key for a given `dayjs` date and time from the backend.
export async function getPrivateKey(pkiID, datetime) {
  const resp = await fetch(
    backendURL +
      "/v0/get_private_key?pki_id=" +
      pkiID +
      "&time=" +
      datetime.unix()
  );
  if (resp.status != 200) {
    throw new Error(resp.statusText + ": " + (await resp.text()));
  }

  let ret = await resp.json();
  ret.pkcs8 = base64Decode(ret.pkcs8);
  return ret;
}
