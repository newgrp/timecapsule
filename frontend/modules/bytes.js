// Converts a `string` to a `Uint8Array` by UTF-8 encoding.
export function utf8Encode(s) {
  return new TextEncoder().encode(s);
}

// Converts a `Uint8Array` to a `string` by UTF-8 decoding.
export function utf8Decode(s) {
  return new TextDecoder().decode(s);
}

// Converts a base64-encoded `string` to a `Uint8Array`.
export function base64Decode(base64) {
  const binString = atob(base64);
  return Uint8Array.from(binString, (m) => m.charCodeAt(0));
}

// Converts a `Uint8Array` to a base64-encoded `string`.
export function base64Encode(bytes) {
  const binString = String.fromCharCode.apply(null, new Uint8Array(bytes));
  return btoa(binString);
}

// Concatenates byte arrays.
export function concatByteArrays(...arrays) {
  let u8arrays = arrays.map((arr) => new Uint8Array(arr));

  let length = 0;
  for (const arr of u8arrays) {
    length += arr.length;
  }

  let ret = new Uint8Array(length);
  let idx = 0;
  for (const arr of u8arrays) {
    ret.set(arr, idx);
    idx += arr.length;
  }
  return ret;
}
