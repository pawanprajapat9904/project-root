// Generate a random key
function generateKey() {
    const key = CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex); // 128-bit key
    document.getElementById('encryptionKey').value = key;
}

// Encrypt data using AES
function encryptData() {
    const input = document.getElementById('encryptionInput').value;
    const key = document.getElementById('encryptionKey').value;

    if (!key || key.length !== 32) {
        alert('Please generate a valid 128-bit key.');
        return;
    }

    const keyBytes = CryptoJS.enc.Hex.parse(key);
    const iv = CryptoJS.lib.WordArray.random(16); // Random IV for each encryption
    const encrypted = CryptoJS.AES.encrypt(input, keyBytes, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    // Combine IV and encrypted data for decryption
    const encryptedData = iv.toString(CryptoJS.enc.Hex) + ':' + encrypted.toString();
    document.getElementById('encryptionOutput').value = encryptedData;
}

// Decrypt data using AES
function decryptData() {
    const input = document.getElementById('decryptionInput').value;
    const key = document.getElementById('decryptionKey').value;

    if (!key || key.length !== 32) {
        alert('Please provide a valid 128-bit key.');
        return;
    }

    const [ivHex, encryptedData] = input.split(':');
    const keyBytes = CryptoJS.enc.Hex.parse(key);
    const iv = CryptoJS.enc.Hex.parse(ivHex);

    const decrypted = CryptoJS.AES.decrypt(encryptedData, keyBytes, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
    document.getElementById('decryptionOutput').value = decryptedText;
}
