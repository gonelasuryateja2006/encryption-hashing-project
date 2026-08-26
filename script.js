const toast = document.getElementById('toast');
const tabButtons = Array.from(document.querySelectorAll('.tab-button'));
const tabPanels = Array.from(document.querySelectorAll('.tab-panel'));
const copyButtons = Array.from(document.querySelectorAll('[data-copy]'));

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(showToast.hideTimeout);
  showToast.hideTimeout = setTimeout(() => toast.classList.remove('visible'), 2500);
}

function updateCounter(input, outputId) {
  const count = input.value.length;
  document.getElementById(outputId).textContent = `${count} characters`;
}

function handleTabSwitch(event) {
  const targetTab = event.currentTarget.dataset.tab;
  tabButtons.forEach((button) => button.classList.toggle('active', button === event.currentTarget));
  tabPanels.forEach((panel) => panel.classList.toggle('active', panel.id === targetTab));
}

function normalizeShift(value) {
  const shift = Number(value);
  if (Number.isNaN(shift)) return 0;
  return ((shift % 26) + 26) % 26;
}

function caesarShiftChar(char, shift) {
  const code = char.charCodeAt(0);
  if (code >= 65 && code <= 90) {
    return String.fromCharCode(((code - 65 + shift) % 26) + 65);
  }
  if (code >= 97 && code <= 122) {
    return String.fromCharCode(((code - 97 + shift) % 26) + 97);
  }
  return char;
}

function caesarCipher(message, shift, encrypt = true) {
  const delta = encrypt ? normalizeShift(shift) : normalizeShift(-shift);
  return Array.from(message).map((character) => caesarShiftChar(character, delta)).join('');
}

function vigenereCipher(message, key, encrypt = true) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  const normalizedKey = key.toLowerCase().replace(/[^a-z]/g, '');
  if (!normalizedKey) return '';
  let keyIndex = 0;
  return Array.from(message).map((char) => {
    const code = char.charCodeAt(0);
    const isUpper = code >= 65 && code <= 90;
    const isLower = code >= 97 && code <= 122;
    if (!isUpper && !isLower) return char;
    const shift = alphabet.indexOf(normalizedKey[keyIndex % normalizedKey.length]);
    keyIndex += 1;
    const base = isUpper ? 65 : 97;
    const offset = char.charCodeAt(0) - base;
    const delta = encrypt ? shift : 26 - shift;
    return String.fromCharCode(((offset + delta) % 26) + base);
  }).join('');
}

function textToUint8(text) {
  return new TextEncoder().encode(text);
}

function base64FromArrayBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => binary += String.fromCharCode(b));
  return btoa(binary);
}

function arrayBufferFromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function deriveAESKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textToUint8(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 200000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

async function encryptAES(message, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAESKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    textToUint8(message)
  );
  const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.byteLength);
  combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);
  return {
    cipherText: base64FromArrayBuffer(combined.buffer),
    salt: base64FromArrayBuffer(salt.buffer),
    iv: base64FromArrayBuffer(iv.buffer)
  };
}

async function decryptAES(base64, password) {
  const data = new Uint8Array(arrayBufferFromBase64(base64));
  if (data.length < 28) throw new Error('Invalid ciphertext format.');
  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const ciphertext = data.slice(28);
  const key = await deriveAESKey(password, salt.buffer);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  return new TextDecoder().decode(plaintext);
}

async function digestSHA256(text) {
  const hash = await crypto.subtle.digest('SHA-256', textToUint8(text));
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function md5(message) {
  function rotateLeft(lValue, iShiftBits) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }

  function addUnsigned(lX, lY) {
    const lX4 = lX & 0x40000000;
    const lY4 = lY & 0x40000000;
    const lX8 = lX & 0x80000000;
    const lY8 = lY & 0x80000000;
    const lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
    if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return lResult ^ 0xC0000000 ^ lX8 ^ lY8;
      return lResult ^ 0x40000000 ^ lX8 ^ lY8;
    }
    return lResult ^ lX8 ^ lY8;
  }

  function convertToWordArray(str) {
    const lWordCount = ((str.length + 8) >> 6) + 1;
    const lWordArray = new Array(lWordCount * 16).fill(0);
    for (let i = 0; i < str.length; i += 1) {
      lWordArray[i >> 2] |= str.charCodeAt(i) << ((i % 4) * 8);
    }
    lWordArray[str.length >> 2] |= 0x80 << ((str.length % 4) * 8);
    lWordArray[lWordCount * 16 - 2] = str.length * 8;
    return lWordArray;
  }

  function wordToHex(lValue) {
    let wordToHexValue = '';
    for (let j = 0; j <= 3; j += 1) {
      const byte = (lValue >>> (j * 8)) & 255;
      wordToHexValue += (`0${byte.toString(16)}`).slice(-2);
    }
    return wordToHexValue;
  }

  function ff(a, b, c, d, x, s, ac) {
    return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, (b & c) | (~b & d)), addUnsigned(x, ac)), s), b);
  }
  function gg(a, b, c, d, x, s, ac) {
    return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, (b & d) | (c & ~d)), addUnsigned(x, ac)), s), b);
  }
  function hh(a, b, c, d, x, s, ac) {
    return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, b ^ c ^ d), addUnsigned(x, ac)), s), b);
  }
  function ii(a, b, c, d, x, s, ac) {
    return addUnsigned(rotateLeft(addUnsigned(addUnsigned(a, c ^ (b | ~d)), addUnsigned(x, ac)), s), b);
  }

  const x = convertToWordArray(message);
  let a = 0x67452301;
  let b = 0xEFCDAB89;
  let c = 0x98BADCFE;
  let d = 0x10325476;

  for (let k = 0; k < x.length; k += 16) {
    const originalA = a;
    const originalB = b;
    const originalC = c;
    const originalD = d;

    a = ff(a, b, c, d, x[k + 0], 7, 0xD76AA478);
    d = ff(d, a, b, c, x[k + 1], 12, 0xE8C7B756);
    c = ff(c, d, a, b, x[k + 2], 17, 0x242070DB);
    b = ff(b, c, d, a, x[k + 3], 22, 0xC1BDCEEE);
    a = ff(a, b, c, d, x[k + 4], 7, 0xF57C0FAF);
    d = ff(d, a, b, c, x[k + 5], 12, 0x4787C62A);
    c = ff(c, d, a, b, x[k + 6], 17, 0xA8304613);
    b = ff(b, c, d, a, x[k + 7], 22, 0xFD469501);
    a = ff(a, b, c, d, x[k + 8], 7, 0x698098D8);
    d = ff(d, a, b, c, x[k + 9], 12, 0x8B44F7AF);
    c = ff(c, d, a, b, x[k + 10], 17, 0xFFFF5BB1);
    b = ff(b, c, d, a, x[k + 11], 22, 0x895CD7BE);
    a = ff(a, b, c, d, x[k + 12], 7, 0x6B901122);
    d = ff(d, a, b, c, x[k + 13], 12, 0xFD987193);
    c = ff(c, d, a, b, x[k + 14], 17, 0xA679438E);
    b = ff(b, c, d, a, x[k + 15], 22, 0x49B40821);

    a = gg(a, b, c, d, x[k + 1], 5, 0xF61E2562);
    d = gg(d, a, b, c, x[k + 6], 9, 0xC040B340);
    c = gg(c, d, a, b, x[k + 11], 14, 0x265E5A51);
    b = gg(b, c, d, a, x[k + 0], 20, 0xE9B6C7AA);
    a = gg(a, b, c, d, x[k + 5], 5, 0xD62F105D);
    d = gg(d, a, b, c, x[k + 10], 9, 0x02441453);
    c = gg(c, d, a, b, x[k + 15], 14, 0xD8A1E681);
    b = gg(b, c, d, a, x[k + 4], 20, 0xE7D3FBC8);
    a = gg(a, b, c, d, x[k + 9], 5, 0x21E1CDE6);
    d = gg(d, a, b, c, x[k + 14], 9, 0xC33707D6);
    c = gg(c, d, a, b, x[k + 3], 14, 0xF4D50D87);
    b = gg(b, c, d, a, x[k + 8], 20, 0x455A14ED);
    a = gg(a, b, c, d, x[k + 13], 5, 0xA9E3E905);
    d = gg(d, a, b, c, x[k + 2], 9, 0xFCEFA3F8);
    c = gg(c, d, a, b, x[k + 7], 14, 0x676F02D9);
    b = gg(b, c, d, a, x[k + 12], 20, 0x8D2A4C8A);

    a = hh(a, b, c, d, x[k + 5], 4, 0xFFFA3942);
    d = hh(d, a, b, c, x[k + 8], 11, 0x8771F681);
    c = hh(c, d, a, b, x[k + 11], 16, 0x6D9D6122);
    b = hh(b, c, d, a, x[k + 14], 23, 0xFDE5380C);
    a = hh(a, b, c, d, x[k + 1], 4, 0xA4BEEA44);
    d = hh(d, a, b, c, x[k + 4], 11, 0x4BDECFA9);
    c = hh(c, d, a, b, x[k + 7], 16, 0xF6BB4B60);
    b = hh(b, c, d, a, x[k + 10], 23, 0xBEBFBC70);
    a = hh(a, b, c, d, x[k + 13], 4, 0x289B7EC6);
    d = hh(d, a, b, c, x[k + 0], 11, 0xEAA127FA);
    c = hh(c, d, a, b, x[k + 3], 16, 0xD4EF3085);
    b = hh(b, c, d, a, x[k + 6], 23, 0x04881D05);
    a = hh(a, b, c, d, x[k + 9], 4, 0xD9D4D039);
    d = hh(d, a, b, c, x[k + 12], 11, 0xE6DB99E5);
    c = hh(c, d, a, b, x[k + 15], 16, 0x1FA27CF8);
    b = hh(b, c, d, a, x[k + 2], 23, 0xC4AC5665);

    a = ii(a, b, c, d, x[k + 0], 6, 0xF4292244);
    d = ii(d, a, b, c, x[k + 7], 10, 0x432AFF97);
    c = ii(c, d, a, b, x[k + 14], 15, 0xAB9423A7);
    b = ii(b, c, d, a, x[k + 5], 21, 0xFC93A039);
    a = ii(a, b, c, d, x[k + 12], 6, 0x655B59C3);
    d = ii(d, a, b, c, x[k + 3], 10, 0x8F0CCC92);
    c = ii(c, d, a, b, x[k + 10], 15, 0xFFEFF47D);
    b = ii(b, c, d, a, x[k + 1], 21, 0x85845DD1);
    a = ii(a, b, c, d, x[k + 8], 6, 0x6FA87E4F);
    d = ii(d, a, b, c, x[k + 15], 10, 0xFE2CE6E0);
    c = ii(c, d, a, b, x[k + 6], 15, 0xA3014314);
    b = ii(b, c, d, a, x[k + 13], 21, 0x4E0811A1);
    a = ii(a, b, c, d, x[k + 4], 6, 0xF7537E82);
    d = ii(d, a, b, c, x[k + 11], 10, 0xBD3AF235);
    c = ii(c, d, a, b, x[k + 2], 15, 0x2AD7D2BB);
    b = ii(b, c, d, a, x[k + 9], 21, 0xEB86D391);

    a = addUnsigned(a, originalA);
    b = addUnsigned(b, originalB);
    c = addUnsigned(c, originalC);
    d = addUnsigned(d, originalD);
  }

  return `${wordToHex(a)}${wordToHex(b)}${wordToHex(c)}${wordToHex(d)}`;
}

async function handleEncryptionForms() {
  const caesarMessage = document.getElementById('caesar-message');
  const caesarShift = document.getElementById('caesar-shift');
  const caesarResult = document.getElementById('caesar-result');
  const vigenereMessage = document.getElementById('vigenere-message');
  const vigenereKey = document.getElementById('vigenere-key');
  const vigenereResult = document.getElementById('vigenere-result');
  const aesMessage = document.getElementById('aes-message');
  const aesPassword = document.getElementById('aes-password');
  const aesResult = document.getElementById('aes-result');
  const aesIv = document.getElementById('aes-iv');
  const aesSalt = document.getElementById('aes-salt');
  const aesToggle = document.getElementById('aes-toggle');

  document.getElementById('caesar-encrypt').addEventListener('click', () => {
    if (!caesarMessage.value.trim()) return showToast('⚠ Please enter a message.');
    caesarResult.value = caesarCipher(caesarMessage.value, caesarShift.value, true);
    showToast('✓ Caesar encrypted');
  });

  document.getElementById('caesar-decrypt').addEventListener('click', () => {
    if (!caesarResult.value.trim()) return showToast('⚠ Please enter ciphertext.');
    caesarMessage.value = caesarCipher(caesarResult.value, caesarShift.value, false);
    updateCounter(caesarMessage, 'caesar-count');
    showToast('✓ Caesar decrypted');
  });

  document.getElementById('caesar-clear').addEventListener('click', () => {
    caesarMessage.value = '';
    caesarShift.value = 3;
    caesarResult.value = '';
    updateCounter(caesarMessage, 'caesar-count');
    showToast('✓ Caesar fields cleared');
  });

  document.getElementById('vigenere-encrypt').addEventListener('click', () => {
    if (!vigenereMessage.value.trim()) return showToast('⚠ Please enter a message.');
    if (!/^[A-Za-z]+$/.test(vigenereKey.value.trim())) return showToast('⚠ Key must contain letters only.');
    vigenereResult.value = vigenereCipher(vigenereMessage.value, vigenereKey.value, true);
    showToast('✓ Vigenère encrypted');
  });

  document.getElementById('vigenere-decrypt').addEventListener('click', () => {
    if (!vigenereResult.value.trim()) return showToast('⚠ Please enter ciphertext.');
    if (!/^[A-Za-z]+$/.test(vigenereKey.value.trim())) return showToast('⚠ Key must contain letters only.');
    vigenereMessage.value = vigenereCipher(vigenereResult.value, vigenereKey.value, false);
    updateCounter(vigenereMessage, 'vigenere-count');
    showToast('✓ Vigenère decrypted');
  });

  document.getElementById('vigenere-clear').addEventListener('click', () => {
    vigenereMessage.value = '';
    vigenereKey.value = '';
    vigenereResult.value = '';
    updateCounter(vigenereMessage, 'vigenere-count');
    showToast('✓ Vigenère fields cleared');
  });

  aesToggle.addEventListener('click', () => {
    const type = aesPassword.type === 'password' ? 'text' : 'password';
    aesPassword.type = type;
    aesToggle.textContent = type === 'password' ? 'Show' : 'Hide';
  });

  document.getElementById('aes-encrypt').addEventListener('click', async () => {
    if (!aesMessage.value.trim()) return showToast('⚠ Please enter a message.');
    if (!aesPassword.value) return showToast('⚠ Please enter a password.');
    try {
      const { cipherText, salt, iv } = await encryptAES(aesMessage.value, aesPassword.value);
      aesResult.value = cipherText;
      aesSalt.textContent = salt;
      aesIv.textContent = iv;
      showToast('✓ AES encrypted');
    } catch (error) {
      showToast('⚠ AES encryption failed');
      console.error(error);
    }
  });

  document.getElementById('aes-decrypt').addEventListener('click', async () => {
    if (!aesResult.value.trim()) return showToast('⚠ Please enter ciphertext.');
    if (!aesPassword.value) return showToast('⚠ Please enter a password.');
    try {
      const plaintext = await decryptAES(aesResult.value.trim(), aesPassword.value);
      aesMessage.value = plaintext;
      showToast('✓ AES decrypted');
    } catch (error) {
      showToast('⚠ AES decryption failed');
      console.error(error);
    }
  });

  document.getElementById('aes-clear').addEventListener('click', () => {
    aesMessage.value = '';
    aesPassword.value = '';
    aesResult.value = '';
    aesSalt.textContent = 'n/a';
    aesIv.textContent = 'n/a';
    updateCounter(aesMessage, 'aes-count');
    showToast('✓ AES fields cleared');
  });
}

async function handleHashingForms() {
  const shaMessage = document.getElementById('sha-message');
  const shaResult = document.getElementById('sha-result');
  const md5Message = document.getElementById('md5-message');
  const md5Result = document.getElementById('md5-result');

  document.getElementById('sha-generate').addEventListener('click', async () => {
    if (!shaMessage.value.trim()) return showToast('⚠ Please enter text.');
    shaResult.value = await digestSHA256(shaMessage.value);
    showToast('✓ SHA-256 generated');
  });

  document.getElementById('sha-clear').addEventListener('click', () => {
    shaMessage.value = '';
    shaResult.value = '';
    updateCounter(shaMessage, 'sha-count');
    showToast('✓ SHA-256 fields cleared');
  });

  document.getElementById('md5-generate').addEventListener('click', () => {
    if (!md5Message.value.trim()) return showToast('⚠ Please enter text.');
    md5Result.value = md5(md5Message.value);
    showToast('✓ MD5 generated');
  });

  document.getElementById('md5-clear').addEventListener('click', () => {
    md5Message.value = '';
    md5Result.value = '';
    updateCounter(md5Message, 'md5-count');
    showToast('✓ MD5 fields cleared');
  });
}

function wireCopyButtons() {
  copyButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      const targetId = button.dataset.copy;
      const field = document.getElementById(targetId);
      if (!field || !field.value.trim()) return showToast('⚠ Nothing to copy.');
      try {
        await navigator.clipboard.writeText(field.value);
        showToast('✓ Text copied to clipboard');
      } catch (error) {
        showToast('⚠ Unable to copy');
      }
    });
  });
}

function wireInputs() {
  const counters = [
    { id: 'caesar-message', output: 'caesar-count' },
    { id: 'vigenere-message', output: 'vigenere-count' },
    { id: 'aes-message', output: 'aes-count' },
    { id: 'sha-message', output: 'sha-count' },
    { id: 'md5-message', output: 'md5-count' }
  ];
  counters.forEach(({ id, output }) => {
    const input = document.getElementById(id);
    updateCounter(input, output);
    input.addEventListener('input', () => updateCounter(input, output));
  });
}

function wireTabs() {
  tabButtons.forEach((button) => button.addEventListener('click', handleTabSwitch));
}

document.addEventListener('DOMContentLoaded', async () => {
  wireTabs();
  wireInputs();
  wireCopyButtons();
  await handleEncryptionForms();
  await handleHashingForms();
});