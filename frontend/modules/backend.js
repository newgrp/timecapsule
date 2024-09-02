import { base64Decode } from "./bytes.js";

const tempPkiName = "Placeholder PKI";
const tempPkiID = "2d2e92bc-3b12-4399-8db1-94bed67ac672";

// Fetches the public key for a given `dayjs` date and time from the backend.
export async function getPublicKey(datetime) {
  const tempKey =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEunp/zYbc+mMz88BWdQ18LgLGjih363YWhl7SADFE6gr0a1UD5Xt0mo5HvXG3c9OCEbbPSjBALglbo7HcqDFtuA==";

  return {
    pkiName: tempPkiName,
    pkiID: tempPkiID,
    spki: base64Decode(tempKey),
  };
}

// Fetches the private key for a given `dayjs` date and time from the backend.
export async function getPrivateKey(pkiID, datetime) {
  const tempKey =
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1t9edLackf/bm/356bTu65Z3kazN4EX8v986JyjRDAChRANCAAS6en/Nhtz6YzPzwFZ1DXwuAsaOKHfrdhaGXtIAMUTqCvRrVQPle3Sajke9cbdz04IRts9KMEAuCVujsdyoMW24";

  if (pkiID != tempPkiID) {
    throw new Error("Unknown PKI: " + pkiID);
  }
  return {
    pkiName: tempPkiName,
    pkiID: tempPkiID,
    pkcs8: base64Decode(tempKey),
  };
}
