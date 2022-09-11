const assert = require('assert');
const method = require('../src/index.js');

const publicKeyJwk = {
  // eslint-disable-next-line max-len
  // kid: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:T9XxxVUPtvL7tgGL9Y8jTxXCOT1LF7nSesZytwqi5S8',
  kty: 'EC',
  crv: 'P-256',
  alg: 'ES256',
  x: 'p01AACad5aWaZfW00mxjSGHTn5Gui7vzpfjBmC_faGA',
  y: 's4xcAXRuhCVta6bh_Uss7xNv4gyRDUAnRKcsFRB32oY',
}

;(async () => {
  const kid1 = await method.calculateJwkThumbprint(publicKeyJwk);

  assert(
      kid1,
      'T9XxxVUPtvL7tgGL9Y8jTxXCOT1LF7nSesZytwqi5S8',
      'can compute JWK Thumbprint',
  );

  const kid2 = await method.calculateJwkThumbprintUri(publicKeyJwk);

  assert(
      kid2,
      // eslint-disable-next-line max-len
      'urn:ietf:params:oauth:jwk-thumbprint:sha-256:T9XxxVUPtvL7tgGL9Y8jTxXCOT1LF7nSesZytwqi5S8',
      'can compute JWK Thumbprint URI',
  );
})();
