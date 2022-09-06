const assert = require('assert');
const method = require('../src/index.js');

const message = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door.',
)
;(async () => {
  const {publicKeyJwk, privateKeyJwk} = await method.generateKeyPair(
      'RSA-OAEP-256',
  );
  const jwe = await method.encryptToKey(message, publicKeyJwk);
  const decryption = await method.decryptWithKey(jwe, privateKeyJwk);
  assert(decryption.plaintext.toString('hex'), message.toString('hex'));
})()
;(async () => {
  const {publicKeyJwk, privateKeyJwk} = await method.generateKeyPair(
      'ECDH-ES+A256KW',
  );
  const jwe = await method.encryptToKey(message, publicKeyJwk);
  const decryption = await method.decryptWithKey(jwe, privateKeyJwk);
  assert(decryption.plaintext.toString('hex'), message.toString('hex'));
})()
;(async () => {
  const {privateKeyJwk} = await method.generateKeyPairForOperation('sign');
  const jws = await method.signAsDid(message, privateKeyJwk);
  const verified = await method.verifyFromDid(jws);
  assert(
      verified.payload.toString('hex'),
      message.toString('hex'),
      'Can sign and verify with recommended signature key',
  );
})();
