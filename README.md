# did-jwk

```bash
npm i @or13/did-jwk --save

# install cli globally
npm i -g @or13/did-jwk
```

## Development

```bash
npm i
npm t

# to test the cli.
npm i -g .
```

## CLI

### Generate Key

Create a private key

```
npm run did-jwk generate-key EdDSA --silent > ./src/cli-examples/key.json
```

### Generate Key For Operation

Create a private key

```
npm run did-jwk generate-for authenticity --silent > ./src/cli-examples/key.authenticity.json
npm run did-jwk generate-for privacy --silent > ./src/cli-examples/key.privacy.json
```

### Create DID

Create a DID.

```
npm run did-jwk create ./src/cli-examples/key.json --silent > ./src/cli-examples/id.json
npm run did-jwk create ./src/cli-examples/key.privacy.json --silent > ./src/cli-examples/id.encrypt.json
```

### Resolve DID

Resolve a DID

```
npm run did-jwk resolve `cat  ./src/cli-examples/id.json | jq '.id'` --silent > ./src/cli-examples/resolution.json
```

### Dereference DID

Dereference a DID.

```
npm run did-jwk dereference `cat  ./src/cli-examples/id.json | jq '.id'`#0 --silent > ./src/cli-examples/dereference.json
```

### Sign

Sign as a DID

```
npm run did-jwk sign ./src/cli-examples/key.json ./src/cli-examples/message.json --silent > ./src/cli-examples/message.signed.json
```

### Verify

Verify with a DID

```
npm run did-jwk verify ./src/cli-examples/message.signed.json --silent > ./src/cli-examples/message.verified.json
```

Verify and decode

```
npm run did-jwk verify ./src/cli-examples/message.signed.json  -- --decode
```

### Encrypt to a DID

Encrypt to a DID

```
npm run did-jwk encrypt `cat  ./src/cli-examples/id.encrypt.json | jq '.id'` ./src/cli-examples/message.json --silent > ./src/cli-examples/message.encrypted.json
```

### Encrypt with a Private Key

Decrypt with a private key

```
npm run did-jwk decrypt ./src/cli-examples/key.privacy.json ./src/cli-examples/message.encrypted.json --silent > ./src/cli-examples/message.decrypted.json
```

Decrypt and decode as text

```
npm run did-jwk decrypt ./src/cli-examples/key.privacy.json ./src/cli-examples/message.encrypted.json -- --decode
```
