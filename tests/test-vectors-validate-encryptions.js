const assert = require('assert');
const method = require('../src/index.js');

const encryptionTestVectors = require('../src/encryption-test-vectors.json');

const messages = [
  new TextEncoder().encode(
      'It’s a dangerous business, Frodo, going out your door.',
  ),
  Buffer.from('deadbeef', 'hex'),
]

;(async () => {
  for (const alg of Object.keys(encryptionTestVectors)) {
    // console.log(alg);
    for (const vector of encryptionTestVectors[alg]) {
      const {didDocument, privateKeyJwk} = vector;
      // console.log(didDocument.id);
      for (const message of messages) {
        const jwe = await method.encryptToDid(message, didDocument.id);
        const decryption = await method.decryptWithKey(jwe, privateKeyJwk);
        assert(decryption.plaintext.toString('hex'), message.toString('hex'));
      }
    }
  }
})();
