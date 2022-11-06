import { webcrypto } from 'node:crypto';
import crypto from 'node:crypto';

// Random UUID
console.log(webcrypto.randomUUID());

// Random values
console.log(
  webcrypto.getRandomValues(new Uint16Array(10))
);
console.log(
  webcrypto.getRandomValues(new Uint32Array(10))
);
console.log(
  webcrypto.getRandomValues(new BigUint64Array(10))
);

// Generate AES-CBC
const aesCbc256 = await webcrypto.subtle.generateKey({
  name: 'AES-CBC',
  length: 256,
}, true, [ 'encrypt', 'decrypt' ]);

// Export import example
const aesCbc256Secret = await webcrypto.subtle.exportKey('raw', aesCbc256);

const aesCbc256Imported = await webcrypto.subtle.importKey(
  'raw', aesCbc256Secret, 'AES-CBC', true, [ 'encrypt', 'decrypt']
);

console.log(aesCbc256, aesCbc256Secret, aesCbc256Imported);

// Key exchange using ECDH with AES-256-GCM encryption
async function ecdhWithAes256Gcm() {
  const ecdhAlice = await webcrypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-384',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  const ecdhBob = await webcrypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-384',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  console.log(
    await webcrypto.subtle.exportKey('jwk', ecdhBob.privateKey));

  const sharedSecret = await webcrypto.subtle.deriveBits({
    name: 'ECDH',
    public: ecdhBob.publicKey,
  }, ecdhAlice.privateKey, 384);

  const bobKey = await webcrypto.subtle.deriveKey({
    name: 'ECDH',
    public: ecdhAlice.publicKey,
  }, ecdhBob.privateKey, {
    name: 'AES-GCM',
    length: 256,
  }, true, [ 'encrypt', 'decrypt' ]);

  const aliceKey = await webcrypto.subtle.deriveKey({
    name: 'ECDH',
    public: ecdhBob.publicKey,
  }, ecdhAlice.privateKey, {
    name: 'AES-GCM',
    length: 256,
  }, true, [ 'encrypt', 'decrypt' ]);

  console.log();
  console.log(
    // await webcrypto.subtle.exportKey('raw', ecdhBob.publicKey),
    // await webcrypto.subtle.exportKey('raw', ecdhAlice.publicKey),
    // await webcrypto.subtle.exportKey('raw', bobKey),
    sharedSecret,
    await webcrypto.subtle.exportKey('raw', aliceKey)
  );

  // process.exit(1);

  const plainText = Buffer.from('TESTABCfakfak', 'utf8');

  const iv = await webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aliceKey, plainText);

  // Send encrypted+iv

  const decrypted = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, bobKey, encrypted);

  console.log(
    encrypted.byteLength, (encrypted.byteLength - plainText.byteLength),
    Buffer.from(decrypted).toString('utf8')
  );
}

// Key exchange using ECDH with AES-128-CBC encryption
async function ecdhWithAes128Cbc() {
  const ecdhAlice = await webcrypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-256',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  const ecdhBob = await webcrypto.subtle.generateKey({
    name: 'ECDH',
    namedCurve: 'P-256',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  const bobKey = await webcrypto.subtle.deriveKey({
    name: 'ECDH',
    public: ecdhAlice.publicKey,
  }, ecdhBob.privateKey, {
    name: 'AES-CBC',
    length: 128
  }, true, [ 'encrypt', 'decrypt' ]);

  const aliceKey = await webcrypto.subtle.deriveKey({
    name: 'ECDH',
    public: ecdhBob.publicKey,
  }, ecdhAlice.privateKey, {
    name: 'AES-CBC',
    length: 128
  }, true, [ 'encrypt', 'decrypt' ]);

  console.log(
    await webcrypto.subtle.exportKey('raw', ecdhBob.publicKey),
    await webcrypto.subtle.exportKey('raw', ecdhAlice.publicKey),
    await webcrypto.subtle.exportKey('raw', bobKey),
    await webcrypto.subtle.exportKey('raw', aliceKey)
  );

  const plainText = Buffer.from('TESTABCfakfak12', 'utf8');

  const iv = await webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-CBC', iv }, aliceKey, plainText);

  // Send encrypted+iv

  const decrypted = await webcrypto.subtle.decrypt({ name: 'AES-CBC', iv }, bobKey, encrypted);

  console.log(
    encrypted.byteLength, (encrypted.byteLength - plainText.byteLength),
    Buffer.from(decrypted).toString('utf8')
  );
}

async function ecdhImportNodeCryptoToWebcrypto() {
  const alice = crypto.createECDH('secp384r1');
  alice.generateKeys();

  const bob = crypto.createECDH('secp384r1');
  bob.generateKeys();

  // import public key to web crypto (bob end)
  const aliceWebcryptoPublicKey = await webcrypto.subtle.importKey('raw', alice.getPublicKey(), {
    name: 'ECDH',
    namedCurve: 'P-384',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  // import private key to web crypto
  // bob.getPublicKey().at(0); // 0x04 is uncompressed
  const bobWebcryptoPrivateKey = await webcrypto.subtle.importKey('jwk', {
    kty: 'EC',
    crv: 'P-384',
    x: bob.getPublicKey().slice(1).slice(0, 48).toString('base64'),
    y: bob.getPublicKey().slice(1).slice(48).toString('base64'),
    d: bob.getPrivateKey().toString('base64'),
    ext: true,
  }, {
    name: 'ECDH',
    namedCurve: 'P-384',
  }, true, [ 'deriveKey', 'deriveBits' ]);

  const sharedSecret = Buffer.from(
    await webcrypto.subtle.deriveBits({
      name: 'ECDH',
      public: aliceWebcryptoPublicKey,
    }, bobWebcryptoPrivateKey, 384)
  );

  const aliceSecret = alice.computeSecret(bob.getPublicKey());
  const bobSecret = bob.computeSecret(alice.getPublicKey());

  console.log(sharedSecret, sharedSecret.length);
  console.log(aliceSecret, aliceSecret.length);
  console.log(bobSecret, bobSecret.length);
}

async function wrapKeys() {
  const aes256 = await webcrypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256,
  }, true, [ 'encrypt', 'decrypt' ]);

  // encrypt using AES-KW (iv not needed)
  const enc1Key = await webcrypto.subtle.generateKey({
    name: 'AES-KW',
    length: 256,
  }, true, [ 'wrapKey', 'unwrapKey' ]);
  let encrypted = await webcrypto.subtle.wrapKey('jwk', aes256, enc1Key, 'AES-KW');
  let decrypted = await webcrypto.subtle.unwrapKey(
    'jwk', encrypted, enc1Key, 'AES-KW', 'AES-GCM', true, [ 'encrypt', 'decrypt' ]
  );
  console.log(await webcrypto.subtle.exportKey('jwk', aes256));
  console.log(await webcrypto.subtle.exportKey('jwk', decrypted));

  // encrypt using AES-GCM (requires iv)
  const enc2Iv = webcrypto.getRandomValues(new Uint8Array(16));
  const enc2Key = await webcrypto.subtle.generateKey({
    name: 'AES-GCM',
    length: 256,
  }, true, [ 'wrapKey', 'unwrapKey' ]);
  encrypted = await webcrypto.subtle.wrapKey('jwk', aes256, enc2Key, { name: 'AES-GCM', iv: enc2Iv });
  decrypted = await webcrypto.subtle.unwrapKey(
    'jwk', encrypted, enc2Key, { name: 'AES-GCM', iv: enc2Iv }, 'AES-GCM', true, [ 'encrypt', 'decrypt' ]
  );
  console.log(await webcrypto.subtle.exportKey('jwk', aes256));
  console.log(await webcrypto.subtle.exportKey('jwk', decrypted));

  // encrypt using password
  const secretPassword = new TextEncoder().encode('test'); // User input
  const enc3Salt = webcrypto.getRandomValues(new Uint8Array(16)); // Saved in system

  const enc3Secret = await webcrypto.subtle.importKey(
    'raw', secretPassword, 'PBKDF2', false, [ 'deriveBits', 'deriveKey' ]
  );
  const enc3Key = await webcrypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: enc3Salt,
    iterations: 100000,
    hash: 'SHA-256',
  }, enc3Secret, { name: "AES-KW", length: 256 }, true, [ 'wrapKey', 'unwrapKey' ]);
  encrypted = await webcrypto.subtle.wrapKey('jwk', aes256, enc3Key, 'AES-KW');
  decrypted = await webcrypto.subtle.unwrapKey(
    'jwk', encrypted, enc3Key, 'AES-KW', 'AES-GCM', true, [ 'encrypt', 'decrypt' ]
  );
  console.log(await webcrypto.subtle.exportKey('jwk', aes256));
  console.log(await webcrypto.subtle.exportKey('jwk', decrypted));
}

async function hmac() {
  const secret = 'abcdefg';
  const payload = 'I love cupcakes';
  const hash = crypto.createHmac('sha256', secret)
                .update(payload)
                .digest('hex');
  console.log(hash);

  const textEncoder = new TextEncoder();
  const webSecret = await webcrypto.subtle.importKey(
    'raw', textEncoder.encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256'
    },
    true, [ 'sign', 'verify' ]
  );
  const webHash = await webcrypto.subtle.sign(
    'HMAC', webSecret, textEncoder.encode(payload)
  );
  console.log(Buffer.from(webHash).toString('hex'));
}

await ecdhWithAes256Gcm();
await ecdhWithAes128Cbc();

const digestPayload = Buffer.from('ABC');
console.log(
  await webcrypto.subtle.digest('SHA-1',   digestPayload),
  await webcrypto.subtle.digest('SHA-256', digestPayload),
  await webcrypto.subtle.digest('SHA-384', digestPayload),
  await webcrypto.subtle.digest('SHA-512', digestPayload)
);

await ecdhImportNodeCryptoToWebcrypto();
await wrapKeys();
await hmac();
