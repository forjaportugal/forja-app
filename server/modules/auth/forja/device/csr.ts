/**
 * Forja device enrolment: minimal PKCS#10 (CSR) reader.
 *
 * Only what enrolment needs: pull out the SubjectPublicKeyInfo and check the
 * CSR's self-signature, which proves the requester holds the private key
 * (proof of possession) without the key ever leaving the device.
 * Supports ECDSA P-256/P-384 and RSA (PKCS#1 v1.5) with SHA-256/384/512.
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

type Tlv = { tag: number; start: number; headerLength: number; length: number; end: number };

function readTlv(buf: Buffer, offset: number): Tlv {
  if (offset + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[offset];
  let length = buf[offset + 1];
  let headerLength = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 3 || offset + 2 + count > buf.length) throw new Error('bad DER length');
    length = 0;
    for (let i = 0; i < count; i += 1) length = (length << 8) | buf[offset + 2 + i];
    headerLength += count;
  }
  const end = offset + headerLength + length;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, start: offset, headerLength, length, end };
}

function children(buf: Buffer, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let offset = parent.start + parent.headerLength;
  while (offset < parent.end) {
    const child = readTlv(buf, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
}

const SEQUENCE = 0x30;
const OID = 0x06;
const BIT_STRING = 0x03;

function decodeOid(bytes: Buffer): string {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let i = 1; i < bytes.length; i += 1) {
    value = value * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

const SIGNATURE_HASH: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'sha256', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
  '1.2.840.113549.1.1.11': 'sha256', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
};

export type ParsedCsr = { der: Buffer; spki: Buffer; publicKey: KeyObject; keyType: string };

export const MAX_CSR_PEM_LENGTH = 8192;

export function pemToDer(pem: string, label: string): Buffer {
  const match = new RegExp(`-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----`).exec(pem);
  if (!match) throw new Error(`not a PEM ${label}`);
  return Buffer.from(match[1].replace(/\s+/g, ''), 'base64');
}

/** Parses and verifies a PEM CSR; throws on anything malformed or badly signed. */
export function parseAndVerifyCsr(pem: unknown): ParsedCsr {
  if (typeof pem !== 'string' || pem.length > MAX_CSR_PEM_LENGTH) throw new Error('CSR missing or too large');
  const label = pem.includes('BEGIN NEW CERTIFICATE REQUEST') ? 'NEW CERTIFICATE REQUEST' : 'CERTIFICATE REQUEST';
  const der = pemToDer(pem, label);
  const root = readTlv(der, 0);
  if (root.tag !== SEQUENCE || root.end !== der.length) throw new Error('CSR is not one DER sequence');
  const [info, sigAlg, signature] = children(der, root);
  if (!info || !sigAlg || !signature || info.tag !== SEQUENCE || sigAlg.tag !== SEQUENCE || signature.tag !== BIT_STRING) {
    throw new Error('CSR structure invalid');
  }
  const infoParts = children(der, info);
  const spkiTlv = infoParts[2];
  if (!spkiTlv || spkiTlv.tag !== SEQUENCE) throw new Error('CSR has no public key');
  const spki = der.subarray(spkiTlv.start, spkiTlv.end);
  const publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const keyType = publicKey.asymmetricKeyType ?? 'unknown';
  if (keyType === 'rsa') {
    const bits = publicKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (bits < 2048) throw new Error('RSA key too small');
  } else if (keyType === 'ec') {
    const curve = publicKey.asymmetricKeyDetails?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'secp384r1') throw new Error('unsupported EC curve');
  } else {
    throw new Error('unsupported key type');
  }

  const algOid = children(der, sigAlg)[0];
  if (!algOid || algOid.tag !== OID) throw new Error('CSR signature algorithm missing');
  const hash = SIGNATURE_HASH[decodeOid(der.subarray(algOid.start + algOid.headerLength, algOid.end))];
  if (!hash) throw new Error('unsupported CSR signature algorithm');

  const sigBytes = der.subarray(signature.start + signature.headerLength + 1, signature.end); // skip unused-bits byte
  const signed = der.subarray(info.start, info.end);
  if (!cryptoVerify(hash, signed, publicKey, sigBytes)) throw new Error('CSR signature invalid');
  return { der, spki: Buffer.from(spki), publicKey, keyType };
}
