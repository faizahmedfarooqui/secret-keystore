/**
 * Server-side keystore singleton
 *
 * IMPORTANT: Only import this file in server-side code:
 * - Server Components
 * - API Routes / Route Handlers
 * - Server Actions
 */

import { createSecretKeyStore, SecretKeyStore } from '@faizahmedfarooqui/secret-keystore';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Global singleton for hot reload persistence
declare global {
  // eslint-disable-next-line no-var
  var __secretKeyStore: SecretKeyStore | undefined;
  // eslint-disable-next-line no-var
  var __secretKeyStorePromise: Promise<SecretKeyStore> | undefined;
}

// Keys that we want to decrypt from the .env.local file
const ENCRYPTED_KEYS = ['API_KEY', 'JWT_SECRET', 'WEBHOOK_SECRET'];

async function initKeyStore(): Promise<SecretKeyStore> {
  if (globalThis.__secretKeyStore) {
    return globalThis.__secretKeyStore;
  }

  if (globalThis.__secretKeyStorePromise) {
    return globalThis.__secretKeyStorePromise;
  }

  console.log('[SecretKeyStore] Initializing...');

  // Read the .env.local file content
  const envPath = path.resolve(process.cwd(), '.env.local');
  let content = '';

  try {
    content = fs.readFileSync(envPath, 'utf-8');
  } catch {
    console.warn('[SecretKeyStore] .env.local not found, trying .env');
    const fallbackPath = path.resolve(process.cwd(), '.env');
    content = fs.readFileSync(fallbackPath, 'utf-8');
  }

  // Get KMS key ID from environment
  const kmsKeyId = process.env.KMS_KEY_ID || process.env.AWS_KMS_KEY_ID;
  if (!kmsKeyId) {
    throw new Error('KMS_KEY_ID or AWS_KMS_KEY_ID environment variable is required');
  }

  // Initialize the keystore with the new API
  globalThis.__secretKeyStorePromise = createSecretKeyStore(
    { type: 'env', content },
    kmsKeyId,
    {
      // Specify which keys to decrypt
      paths: ENCRYPTED_KEYS,

      // AWS configuration
      aws: {
        region: process.env.AWS_REGION || 'us-east-1',
        // Uncomment for local development with explicit credentials:
        // credentials: {
        //   accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
        //   secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        // },
      },

      // Security settings
      security: {
        inMemoryEncryption: true,
        secureWipe: true,
      },

      // Access settings
      access: {
        ttl: null, // Secrets never expire (for demo)
        autoRefresh: true,
      },

      // Validation
      validation: {
        throwOnMissingKey: false, // Don't throw if keys missing (for demo)
      },

      // Custom logger
      logger: {
        debug: (msg: string) => console.debug(`[SecretKeyStore] ${msg}`),
        info: (msg: string) => console.log(`[SecretKeyStore] ${msg}`),
        warn: (msg: string) => console.warn(`[SecretKeyStore] ${msg}`),
        error: (msg: string) => console.error(`[SecretKeyStore] ${msg}`),
      },

      // Attestation (enable in Nitro Enclaves)
      // attestation: {
      //   enabled: true,
      //   required: true,
      //   endpoint: 'http://localhost:8080/attestation',
      // },
    }
  );

  globalThis.__secretKeyStore = await globalThis.__secretKeyStorePromise;
  globalThis.__secretKeyStorePromise = undefined;

  console.log(`[SecretKeyStore] Initialized with ${globalThis.__secretKeyStore.keys().length} secrets`);

  return globalThis.__secretKeyStore;
}

export async function getKeyStore(): Promise<SecretKeyStore> {
  return initKeyStore();
}

export async function getSecret(key: string): Promise<string | undefined> {
  const keyStore = await getKeyStore();
  return keyStore.get(key);
}

export async function hasSecret(key: string): Promise<boolean> {
  const keyStore = await getKeyStore();
  return keyStore.has(key);
}

