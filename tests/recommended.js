const assert = require('assert');
const method = require('../src/index.js')

;(async () => {
  const {publicKeyJwk, privateKeyJwk} =
    await method.generateKeyPairForOperation('sign');
  assert(
      publicKeyJwk.crv,
      'Ed25519',
      'Expect Ed25519 to be recommended for signatures.',
  );
  assert.deepEqual(
      privateKeyJwk.key_ops,
      ['sign'],
      'Expect sign operation on public key.',
  );
  assert.deepEqual(
      publicKeyJwk.key_ops,
      ['verify'],
      'Expect verify operation on public key.',
  );

  const message = Buffer.from('deadbeef', 'hex');
  const jws = await method.signAsDid(message, privateKeyJwk);
  const verified = await method.verifyFromDid(jws);
  assert(
      verified.payload.toString('hex'),
      message.toString('hex'),
      'Can sign and verify with recommended signature key',
  );
})();
