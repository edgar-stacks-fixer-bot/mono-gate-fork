import { execFileSync } from 'node:child_process';
import {
  constants,
  createCipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
  verify,
} from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const pemPath = process.argv[2];
const selfTest = process.argv.includes('--self-test');

function aws(args) {
  return execFileSync('aws', ['kms', ...args, '--output', 'json'], { encoding: 'utf8' });
}

const privateKey = pemPath
  ? createPrivateKey(readFileSync(pemPath, 'utf8'))
  : generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const material = privateKey.export({ format: 'der', type: 'pkcs8' });

const { KeyMetadata } = JSON.parse(
  aws(['create-key', '--key-spec', 'RSA_2048', '--key-usage', 'SIGN_VERIFY', '--origin', 'EXTERNAL'])
);
const keyId = KeyMetadata.KeyId;

const parameters = JSON.parse(
  aws([
    'get-parameters-for-import',
    '--key-id',
    keyId,
    '--wrapping-algorithm',
    'RSA_AES_KEY_WRAP_SHA_256',
    '--wrapping-key-spec',
    'RSA_4096',
  ])
);
const wrappingKey = createPublicKey({
  key: Buffer.from(parameters.PublicKey, 'base64'),
  format: 'der',
  type: 'spki',
});

const aesKey = randomBytes(32);
const wrappedAesKey = publicEncrypt(
  { key: wrappingKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
  aesKey
);
const cipher = createCipheriv('id-aes256-wrap-pad', aesKey, Buffer.from('A65959A6', 'hex'));
const wrappedMaterial = Buffer.concat([cipher.update(material), cipher.final()]);

const scratch = mkdtempSync(path.join(tmpdir(), 'kms-import-'));
try {
  const materialFile = path.join(scratch, 'material.bin');
  const tokenFile = path.join(scratch, 'token.bin');
  writeFileSync(materialFile, Buffer.concat([wrappedAesKey, wrappedMaterial]));
  writeFileSync(tokenFile, Buffer.from(parameters.ImportToken, 'base64'));
  aws([
    'import-key-material',
    '--key-id',
    keyId,
    '--encrypted-key-material',
    `fileb://${materialFile}`,
    '--import-token',
    `fileb://${tokenFile}`,
    '--expiration-model',
    'KEY_MATERIAL_DOES_NOT_EXPIRE',
  ]);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

if (selfTest) {
  const message = Buffer.from('header.payload');
  const digest = createHash('sha256').update(message).digest();
  const signature = execFileSync(
    'aws',
    [
      'kms',
      'sign',
      '--cli-binary-format',
      'base64',
      '--key-id',
      keyId,
      '--message',
      digest.toString('base64'),
      '--message-type',
      'DIGEST',
      '--signing-algorithm',
      'RSASSA_PKCS1_V1_5_SHA_256',
      '--output',
      'text',
      '--query',
      'Signature',
    ],
    { encoding: 'utf8' }
  ).trim();
  const valid = verify(
    'sha256',
    message,
    createPublicKey(privateKey),
    Buffer.from(signature, 'base64')
  );
  console.error(`signature verifies against the imported key: ${valid}`);
  if (!valid) process.exit(1);
}

console.log(keyId);
