import { concatByteArrays } from "./bytes.js";

const ecSEC1PubKeySize = 65;
const aes256KeySize = 32;
const aesCtrBlockSize = 16;
const aesCounterBits = 64;
const hmacSHA256Size = 32;

// Derives AES and HMAC keys from public and private P256 keys via ECDH-HKDF-SHA256.
async function eciesDerive(pub, priv) {
  const hkdfKey = await crypto.subtle.deriveKey(
    /*algorithm=*/ { name: "ECDH", public: pub },
    /*baseKey=*/ priv,
    /*derivedKeyType=*/ {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(),
      info: new ArrayBuffer(),
    },
    /*extractable=*/ false,
    /*keyUsages=*/ ["deriveBits"]
  );
  const hkdfRaw = await crypto.subtle.deriveBits(
    /*algorithm=*/ {
      name: "HKDF",
      hash: "SHA-256",
      salt: new ArrayBuffer(),
      info: new ArrayBuffer(),
    },
    /*baseKey=*/ hkdfKey,
    /*length=*/ 8 * (aes256KeySize + hmacSHA256Size)
  );
  if (hkdfRaw.byteLength < aes256KeySize + hmacSHA256Size) {
    throw new Error("HKDF generated insufficient output");
  }

  const aesRaw = hkdfRaw.slice(0, aes256KeySize);
  const aesKey = await crypto.subtle.importKey(
    /*format=*/ "raw",
    /*keyData=*/ aesRaw,
    /*algorithm=*/ "AES-CTR",
    /*extractable=*/ false,
    /*keyUsages=*/ ["decrypt", "encrypt"]
  );

  const hmacRaw = hkdfRaw.slice(aes256KeySize, aes256KeySize + hmacSHA256Size);
  const hmacKey = await crypto.subtle.importKey(
    /*format=*/ "raw",
    /*keyData=*/ hmacRaw,
    /*algorithm=*/ { name: "HMAC", hash: "SHA-256" },
    /*extractable=*/ false,
    /*keyUsages=*/ ["sign", "verify"]
  );

  return { aesKey: aesKey, hmacKey: hmacKey };
}

// Encrypts the plaintext to the public key using ECIES.
export async function eciesEncrypt(pubKey, plaintext) {
  const ephemeralKey = await crypto.subtle.generateKey(
    /*algorithm=*/ { name: "ECDH", namedCurve: "P-256" },
    /*extractable=*/ true,
    /*keyUsages=*/ ["deriveKey"]
  );
  const ephemeralPub = await crypto.subtle.exportKey(
    /*format=*/ "raw",
    /*key=*/ ephemeralKey.publicKey
  );
  if (ephemeralPub.byteLength != ecSEC1PubKeySize) {
    throw new Error(
      "Ephemeral public key encoded to wrong length: " + ephemeralPub.byteLength
    );
  }

  const eciesKeys = await eciesDerive(pubKey, ephemeralKey.privateKey);

  const ctrBlock = crypto.getRandomValues(new Uint8Array(aesCtrBlockSize));
  const ciphertext = await crypto.subtle.encrypt(
    /*algorithm=*/ {
      name: "AES-CTR",
      counter: ctrBlock,
      length: aesCounterBits,
    },
    /*key=*/ eciesKeys.aesKey,
    /*data=*/ plaintext
  );
  const hmac = await crypto.subtle.sign(
    /*algorithm=*/ "HMAC",
    /*key=*/ eciesKeys.hmacKey,
    /*data=*/ (
      await concatByteArrays(ctrBlock, ciphertext)
    ).buffer
  );

  return concatByteArrays(ephemeralPub, ctrBlock, ciphertext, hmac);
}

// Decrypts the ciphertext using ECIES with the given private key.
export async function eciesDecrypt(privKey, cipherBlob) {
  if (
    cipherBlob.byteLength <
    ecSEC1PubKeySize + aesCtrBlockSize + hmacSHA256Size
  ) {
    throw new Error("Ciphertext is too short");
  }

  const ephemeralPub = cipherBlob.slice(0, ecSEC1PubKeySize);
  const ctrBlock = cipherBlob.slice(
    ecSEC1PubKeySize,
    ecSEC1PubKeySize + aesCtrBlockSize
  );
  const ciphertext = cipherBlob.slice(
    ecSEC1PubKeySize + aesCtrBlockSize,
    -hmacSHA256Size
  );
  const hmac = cipherBlob.slice(-hmacSHA256Size);

  const ephemeralKey = await crypto.subtle.importKey(
    /*format=*/ "raw",
    /*keyData=*/ ephemeralPub,
    /*algorithm=*/ { name: "ECDH", namedCurve: "P-256" },
    /*extractable=*/ false,
    /*keyUsages=*/ ["deriveKey"]
  );
  const eciesKeys = await eciesDerive(ephemeralKey, privKey);

  const ok = await crypto.subtle.verify(
    /*algorithm=*/ "HMAC",
    /*key=*/ eciesKeys.hmacKey,
    /*signature=*/ hmac,
    /*data=*/ (
      await concatByteArrays(ctrBlock, ciphertext)
    ).buffer
  );
  if (!ok) {
    throw new Error("HMAC verification failed");
  }

  return crypto.subtle.decrypt(
    /*algorithm=*/ {
      name: "AES-CTR",
      counter: ctrBlock,
      length: aesCounterBits,
    },
    /*key=*/ eciesKeys.aesKey,
    /*data=*/ ciphertext
  );
}
