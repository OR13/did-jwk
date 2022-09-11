const jose = require('jose');

const methodPrefix = 'did:jwk';

const EdDSA = 'EdDSA';
const ES256K = 'ES256K';
const ES256 = 'ES256';
const ES384 = 'ES384';
const ES512 = 'ES512';

const ECDH_ES_A256KW = 'ECDH-ES+A256KW';
const RSA_OAEP_256 = 'RSA-OAEP-256';

// https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3
// https://www.w3.org/TR/WebCryptoAPI/#subtlecrypto-interface-methods

const signatureAlgorithms = [ES256, ES384, ES512, EdDSA, ES256K];
const encryptionAlgorithms = [ECDH_ES_A256KW, RSA_OAEP_256];

const algorithms = [...signatureAlgorithms, ...encryptionAlgorithms];

const keyOperations = {
  sign: 'compute digital signature or MAC',
  verify: 'verify digital signature or MAC',
  encrypt: 'encrypt content',
  decrypt: 'decrypt content and validate decryption, if applicable',
  wrapKey: 'encrypt key',
  unwrapKey: 'decrypt key and validate decryption, if applicable',
  deriveKey: 'derive key',
  deriveBits: 'derive bits not to be used as a key',
};

const signatureVerificationRelationships = [
  'authentication',
  'assertionMethod',
  'capabilityInvocation',
  'capabilityDelegation',
];
const encryptionVerificationRelationships = ['keyAgreement'];

const formatJwk = (jwk) => {
  const {kid, x5u, x5c, x5t, kty, crv, alg, key_ops, x, y, d, ...rest} = jwk;
  return JSON.parse(
      JSON.stringify({
        kid,
        x5u,
        x5c,
        x5t,
        kty,
        crv,
        alg,
        key_ops,
        x,
        y,
        d,
        ...rest,
      }),
  );
};

const generateKeyPair = async (alg) => {
  const {publicKey, privateKey} = await jose.generateKeyPair(alg);
  const publicKeyJwk = await jose.exportJWK(publicKey);
  const privateKeyJwk = await jose.exportJWK(privateKey);
  const kid = await jose.calculateJwkThumbprintUri(publicKeyJwk);
  return {
    publicKeyJwk: formatJwk({...publicKeyJwk, alg, kid}),
    privateKeyJwk: formatJwk({...privateKeyJwk, alg, kid}),
  };
};

const generateKeyPairForOperation = async (op) => {
  const recommendedAlg = {
    sign: EdDSA,
    encrypt: ECDH_ES_A256KW,
    wrapKey: ECDH_ES_A256KW,
    deriveKey: ECDH_ES_A256KW,
  }[op];
  const {publicKeyJwk, privateKeyJwk} = await generateKeyPair(recommendedAlg);
  switch (op) {
    case 'sign': {
      publicKeyJwk.key_ops = ['verify'];
      privateKeyJwk.key_ops = ['sign'];
      break;
    }
    case 'encrypt': {
      publicKeyJwk.key_ops = ['encrypt'];
      privateKeyJwk.key_ops = ['decrypt'];
      break;
    }
    case 'wrapKey': {
      publicKeyJwk.key_ops = ['wrapKey', 'unwrapKey'];
      privateKeyJwk.key_ops = ['wrapKey', 'unwrapKey'];
      break;
    }
    case 'deriveKey': {
      publicKeyJwk.key_ops = ['deriveKey', 'deriveBits'];
      privateKeyJwk.key_ops = ['deriveKey', 'deriveBits'];
      break;
    }
    default:
      return null;
  }

  return {
    publicKeyJwk: formatJwk(publicKeyJwk),
    privateKeyJwk: formatJwk(privateKeyJwk),
  };
};

const getPublicOperationsFromPrivate = (key_ops) => {
  if (key_ops.includes('sign')) {
    return ['verify'];
  }
  if (key_ops.includes('verify')) {
    return ['encrypt'];
  }
  return key_ops;
};

const toDid = (jwk) => {
  // eslint-disable-next-line no-unused-vars
  const {d, p, q, dp, dq, qi, ...publicKeyJwk} = jwk;
  const id = jose.base64url.encode(JSON.stringify(publicKeyJwk));
  const did = `${methodPrefix}:${id}`;
  return did;
};

const toDidDocument = (jwk) => {
  const {
    // eslint-disable-next-line no-unused-vars
    d,
    p,
    q,
    dp,
    dq,
    qi,

    key_ops,

    ...publicKeyJwk
  } = jwk;

  if (d && key_ops) {
    publicKeyJwk.key_ops = getPublicOperationsFromPrivate(key_ops);
  }

  const did = toDid(publicKeyJwk);
  const vm = {
    id: '#0',
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk,
  };
  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      {'@vocab': 'https://www.iana.org/assignments/jose#'},
    ],
    'id': did,
    'verificationMethod': [vm],
  };
  if (signatureAlgorithms.includes(publicKeyJwk.alg)) {
    signatureVerificationRelationships.forEach((vr) => {
      didDocument[vr] = [vm.id];
    });
  }

  if (encryptionAlgorithms.includes(publicKeyJwk.alg)) {
    encryptionVerificationRelationships.forEach((vr) => {
      didDocument[vr] = [vm.id];
    });
  }

  return didDocument;
};

const resolve = (did) => {
  const decoded = jose.base64url.decode(did.split(':').pop().split('#')[0]);
  const jwk = JSON.parse(decoded.toString());
  return toDidDocument(jwk);
};

const dereference = (didUrl) => {
  const [did, fragment] = didUrl.split('#');
  const didDocument = resolve(did);
  const [vm] = didDocument.verificationMethod;
  if (vm.id === `#${fragment}`) {
    return vm;
  }
  return null;
};

const encryptToKey = async (plaintext, publicKeyJwk) => {
  const publicKey = await jose.importJWK(publicKeyJwk);
  const jwe = await new jose.CompactEncrypt(plaintext)
      .setProtectedHeader({alg: publicKeyJwk.alg, enc: 'A256GCM'})
      .encrypt(publicKey);
  return jwe;
};

const encryptToDidUrl = async (plaintext, didUrl) => {
  const {publicKeyJwk} = dereference(didUrl);
  return encryptToKey(plaintext, publicKeyJwk);
};

const decryptWithKey = async (jwe, privateKeyJwk) => {
  const privateKey = await jose.importJWK(privateKeyJwk);
  const {plaintext, protectedHeader} = await jose.compactDecrypt(
      jwe,
      privateKey,
  );
  return {plaintext, protectedHeader};
};

const sign = async (payload, privateKeyJwk, header = {}) => {
  const privateKey = await jose.importJWK(privateKeyJwk);
  const jws = await new jose.CompactSign(payload)
      .setProtectedHeader({...header, alg: privateKeyJwk.alg})
      .sign(privateKey);
  return jws;
};

const verifyWithKey = async (jws, publicKeyJwk) => {
  const publicKey = await jose.importJWK(publicKeyJwk);
  const {payload, protectedHeader} = await jose.compactVerify(jws, publicKey);
  return {payload, protectedHeader};
};

const signAsDid = (payload, privateKeyJwk, header = {}) => {
  const did = toDid(privateKeyJwk);
  return sign(payload, privateKeyJwk, {iss: did, kid: '#0', ...header});
};

const verifyFromDid = async (jws) => {
  const {iss, kid} = jose.decodeProtectedHeader(jws);
  const {publicKeyJwk} = dereference(iss + kid);
  const publicKey = await jose.importJWK(publicKeyJwk);
  const {payload, protectedHeader} = await jose.compactVerify(jws, publicKey);
  return {payload, protectedHeader};
};

const encryptToDid = async (plaintext, did) => {
  const {publicKeyJwk} = dereference(did + '#0');
  return encryptToKey(plaintext, publicKeyJwk);
};

const calculateJwkThumbprintUri = async (publicKeyJwk) => {
  const kid = await jose.calculateJwkThumbprintUri(publicKeyJwk);
  return kid;
};

const calculateJwkThumbprint = async (publicKeyJwk) => {
  const kid = await calculateJwkThumbprintUri(publicKeyJwk);
  return kid.split(':').pop();
};

class DIDMethodClient {
  constructor(config) {
    if (!config.documentLoader) {
      config.documentLoader = async (iri) => {
        const message = 'Unsuported IRI ' + iri;
        throw new Error(message);
      };
    }

    this.operations = {
      create: async (alg, options = {}) => {
        const {privateKeyJwk} = await generateKeyPair(alg);
        const didDocument = toDidDocument(privateKeyJwk);
        return {privateKeyJwk, didDocument};
      },
      resolve: async (did) => {
        return resolve(did);
      },
    };
  }
}

const utils = {
  signatureAlgorithms,
  encryptionAlgorithms,
  algorithms,
  generateKeyPair,
  generateKeyPairForOperation,
  toDid,
  toDidDocument,
  resolve,
  dereference,
  encryptToKey,
  decryptWithKey,
  encryptToDidUrl,
  sign,
  verifyWithKey,
  signAsDid,
  verifyFromDid,
  encryptToDid,
  calculateJwkThumbprintUri,
  calculateJwkThumbprint,
};

const method = {
  name: methodPrefix,
  create: (config) => {
    return new DIDMethodClient(config);
  },
  ...utils,
};

module.exports = method;
