const assert = require('assert');
const method = require('../src/index.js');

const signatureTestVectors = require('../src/signatures-test-vectors.json');

const messages = [
  new TextEncoder().encode(
      'It’s a dangerous business, Frodo, going out your door.',
  ),
  Buffer.from('deadbeef', 'hex'),
]

;(async () => {
  for (const alg of Object.keys(signatureTestVectors)) {
    // console.log(alg);
    for (const vector of signatureTestVectors[alg]) {
      // console.log(vector);
      const {privateKeyJwk} = vector;
      for (const message of messages) {
        const jws = await method.signAsDid(message, privateKeyJwk);
        const verified = await method.verifyFromDid(jws);
        assert(verified.payload.toString('hex'), message.toString('hex'));
      }
    }
  }
})();
