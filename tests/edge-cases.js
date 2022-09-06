const assert = require('assert');
const method = require('../src/index.js');

const message = new TextEncoder().encode(
    'It’s a dangerous business, Frodo, going out your door.',
)

;(async () => {
  for (const signatureAlg of method.signatureAlgorithms) {
    const {publicKeyJwk} = await method.generateKeyPair(signatureAlg);

    try {
      await method.encryptToKey(message, publicKeyJwk);
    } catch (e) {
      // console.log(e);
      assert(
          e.message,
          'Invalid or unsupported "alg" (JWE Algorithm) header value',
          'Expect encryption to fail when applied to a signature key',
      );
      const didDocument = method.toDidDocument(publicKeyJwk);
      assert.deepEqual(
          didDocument.keyAgreement,
          undefined,
          'When JWE fails, keyAgreement MUST be undefined.',
      );
    }
  }
})()
;(async () => {
  for (const encryptionAlgorithm of method.encryptionAlgorithms) {
    const {privateKeyJwk} = await method.generateKeyPair(encryptionAlgorithm);
    const didDocument = method.toDidDocument(privateKeyJwk);
    try {
      await method.sign(message, privateKeyJwk);
    } catch (e) {
      assert(
          e.message,
          // eslint-disable-next-line max-len
          `alg ${encryptionAlgorithm} is not supported either by JOSE or your javascript runtime`,
      );
      assert.deepEqual(
          didDocument.authentication,
          undefined,
          'When JWS fails, authentication MUST be undefined.',
      );
      assert.deepEqual(
          didDocument.assertionMethod,
          undefined,
          'When JWS fails, assertionMethod MUST be undefined.',
      );
      assert.deepEqual(
          didDocument.capabilityInvocation,
          undefined,
          'When JWS fails, capabilityInvocation MUST be undefined.',
      );
      assert.deepEqual(
          didDocument.capabilityDelegation,
          undefined,
          'When JWS fails, capabilityDelegation MUST be undefined.',
      );
    }
  }
})();
