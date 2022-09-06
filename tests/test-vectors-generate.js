const fs = require('fs');

const method = require('../src/index.js');

const redundancy = 3

;(async () => {
  const fixture = {};

  for (const alg of method.signatureAlgorithms) {
    fixture[alg] = [];
    for (let i = 0; i < redundancy; i++) {
      const {privateKeyJwk} = await method.generateKeyPair(alg);
      const didDocument = method.toDidDocument(privateKeyJwk);
      fixture[alg].push({privateKeyJwk, didDocument});
    }
  }
  fs.writeFileSync(
      '../src/signatures-test-vectors.json',
      JSON.stringify(fixture, null, 2),
  );
})()
;(async () => {
  const fixture = {};

  for (const alg of method.encryptionAlgorithms) {
    fixture[alg] = [];
    for (let i = 0; i < redundancy; i++) {
      const {privateKeyJwk} = await method.generateKeyPair(alg);
      const didDocument = method.toDidDocument(privateKeyJwk);
      fixture[alg].push({privateKeyJwk, didDocument});
    }
  }
  fs.writeFileSync(
      '../src/encryption-test-vectors.json',
      JSON.stringify(fixture, null, 2),
  );
})();
