const assert = require('assert');
const method = require('../src/index.js');

const message = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door.',
)

;(async () => {
  const {privateKeyJwk, publicKeyJwk} =
    await method.generateKeyPairForOperation('sign');
  const jws = await method.signAsDid(message, privateKeyJwk, {
    iss: 'did:example:123',
    kid: '#key-456',
  });
  const verified = await method.verifyWithKey(jws, publicKeyJwk);
  assert(
      verified.payload.toString('hex'),
      message.toString('hex'),
      'Can sign and verify with recommended signature key',
  );
})();
