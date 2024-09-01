import { getPrivateKey, getPublicKey } from "./modules/backend.js";
import {
  base64Decode,
  base64Encode,
  utf8Decode,
  utf8Encode,
} from "./modules/bytes.js";
import { eciesDecrypt, eciesEncrypt } from "./modules/ecies.js";

dayjs.extend(dayjs_plugin_utc);
dayjs.extend(dayjs_plugin_timezone);

// Encrypts a message to the given `dayjs` date and time.
async function encryptMessage(message, datetime) {
  const pubKey = await getPublicKey(datetime);
  const blob = await eciesEncrypt(pubKey, utf8Encode(message));
  return base64Encode(blob);
}

// Decrypts a message for the given `dayjs` date and time.
async function decryptMessage(encryptedMessage, datetime) {
  const keyPair = await getPrivateKey(datetime);
  const decrypted = await eciesDecrypt(keyPair, base64Decode(encryptedMessage));
  return utf8Decode(decrypted);
}

// Auto-populate the datetime box with the current date and time in the user's timezone.
document
  .getElementsByName("datetime")
  .forEach((menu) => (menu.value = dayjs().format("YYYY-MM-DDTHH:mm:ss")));

// Populate the timezone dropdown with all browser-supported values, auto-selecting the user's
// timezone.
const userTZ = dayjs.tz.guess();
console.log("Guessed user time zone:", userTZ);

let tzSelects = document.getElementsByName("timezone");
Intl.supportedValuesOf("timeZone").forEach((tz) => {
  const selected = tz === userTZ;
  tzSelects.forEach((menu) =>
    menu.appendChild(
      new Option(
        /*text=*/ tz,
        /*value=*/ tz,
        /*defaultSelected=*/ false,
        /*selected=*/ selected
      )
    )
  );
});

document
  .getElementById("encryptButton")
  .addEventListener("click", function (e) {
    e.preventDefault();

    const message = document.getElementById("message").value;
    const datetime = dayjs(document.getElementById("encryptDatetime").value);
    // TODO: Compute date in timezone.

    encryptMessage(message, datetime)
      .catch((e) => {
        console.error(e);
      })
      .then((result) => {
        document.getElementById("encryptResult").textContent = result;
      });
  });

document
  .getElementById("decryptButton")
  .addEventListener("click", function (e) {
    e.preventDefault();

    const encryptedMessage = document.getElementById("encryptedMessage").value;
    const datetime = dayjs(document.getElementById("decryptDatetime").value);
    // TODO: Compute date in timezone.

    decryptMessage(encryptedMessage, datetime)
      .catch((e) => {
        console.error(e);
      })
      .then((result) => {
        document.getElementById("decryptResult").textContent = result;
      });
  });
