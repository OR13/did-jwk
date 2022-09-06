#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const yargs = require('yargs');
const {hideBin} = require('yargs/helpers');
const method = require('./index.js');

const config = {};

const client = method.create(config);

const readJsonFromPath = (argv, argName) => {
  let value;
  if (argv[argName]) {
    try {
      const file = fs
          .readFileSync(path.resolve(process.cwd(), argv[argName]))
          .toString();
      value = JSON.parse(file);
    } catch (e) {
      console.error('Cannot read from file: ' + argv[argName]);
      process.exit(1);
    }
  }
  return value;
};

yargs(hideBin(process.argv))
    .scriptName(method.name)
    .command(
        'generate-key <alg>',
        'generate a key pair',
        () => {},
        async (argv) => {
          const {alg} = argv;
          const key = await method.generateKeyPair(alg);
          console.log(JSON.stringify(key.privateKeyJwk, null, 2));
        },
    )
    .command(
        'generate-for <purpose>',
        'generate a key for a purpose',
        () => {},
        async (argv) => {
          const {purpose} = argv;
          const purposeToKeyOp = {
            authenticity: 'sign',
            privacy: 'encrypt',
          };
          const op = purposeToKeyOp[purpose];
          const key = await method.generateKeyPairForOperation(op);
          console.log(JSON.stringify(key.privateKeyJwk, null, 2));
        },
    )
    .command(
        'create <jwk>',
        'create a decentralized identifier',
        () => {},
        async (argv) => {
          let jwk;
          if (argv.jwk) {
            try {
              const file = fs
                  .readFileSync(path.resolve(process.cwd(), argv.jwk))
                  .toString();

              jwk = JSON.parse(file);
            } catch (e) {
              console.error('Cannot base jwk from: ' + argv.jwk);
              process.exit(1);
            }
          }
          const id = method.toDid(jwk);
          console.log(JSON.stringify({id}, null, 2));
        },
    )
    .command(
        'resolve <did>',
        'resolve a decentralized identifier',
        () => {},
        async (argv) => {
          const {did} = argv;
          const resolution = await client.operations.resolve(did);
          console.log(JSON.stringify(resolution, null, 2));
        },
    )
    .command(
        'dereference <didUrl>',
        'dereference a decentralized identifier url',
        () => {},
        async (argv) => {
          const {didUrl} = argv;
          const resolution = await method.dereference(didUrl);
          console.log(JSON.stringify(resolution, null, 2));
        },
    )
    .command(
        'sign <jwk> <msg>',
        'sign a message as a decentralized identifier',
        () => {},
        async (argv) => {
          const jwk = readJsonFromPath(argv, 'jwk');
          const msg = readJsonFromPath(argv, 'msg');
          const message = new TextEncoder().encode(JSON.stringify(msg));
          const jws = await method.signAsDid(message, jwk);
          console.log(JSON.stringify({jws}, null, 2));
        },
    )
    .command(
        'verify <msg>',
        'verify a message signed by a decentralized identifier',
        () => {},
        async (argv) => {
          const {jws} = readJsonFromPath(argv, 'msg');
          const verified = await method.verifyFromDid(jws);

          if (argv.decode) {
            console.log(new TextDecoder().decode(verified.payload));
          } else {
            console.log(JSON.stringify({verified}, null, 2));
          }
        },
    )
    .command(
        'encrypt <did> <msg>',
        'encrypt a message to a decentralized identifier',
        () => {},
        async (argv) => {
          const did = argv.did;
          const msg = readJsonFromPath(argv, 'msg');
          const message = new TextEncoder().encode(JSON.stringify(msg));

          const jwe = await method.encryptToDid(message, did);

          console.log(JSON.stringify({jwe}, null, 2));
        },
    )
    .command(
        'decrypt <jwk> <msg>',
        'encrypt a message to a decentralized identifier',
        () => {},
        async (argv) => {
          const jwk = readJsonFromPath(argv, 'jwk');
          const {jwe} = readJsonFromPath(argv, 'msg');
          const decrypted = await method.decryptWithKey(jwe, jwk);

          if (argv.decode) {
            console.log(new TextDecoder().decode(decrypted.plaintext));
          } else {
            console.log(JSON.stringify({decrypted}, null, 2));
          }
        },
    )
    .demandCommand(1)
    .parse();
