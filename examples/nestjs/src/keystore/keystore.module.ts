import * as fs from 'node:fs';
import * as path from 'node:path';
import { Module, Global, Logger } from '@nestjs/common';
import { createSecretKeyStore, SecretKeyStore } from '@faizahmedfarooqui/secret-keystore';

export const KEYSTORE_TOKEN = 'SECRET_KEYSTORE';

// Keys that we want to decrypt from the .env file
const ENCRYPTED_KEYS = ['API_KEY', 'JWT_SECRET', 'WEBHOOK_SECRET'];

@Global()
@Module({
  providers: [
    {
      provide: KEYSTORE_TOKEN,
      useFactory: async (): Promise<SecretKeyStore> => {
        const logger = new Logger('SecretKeyStore');

        logger.log('Initializing SecretKeyStore...');

        try {
          // Read the .env file content
          const envPath = path.resolve(process.cwd(), '.env');
          const content = fs.readFileSync(envPath, 'utf-8');

          // Get KMS key ID from environment (must be set)
          const kmsKeyId = process.env.KMS_KEY_ID || process.env.AWS_KMS_KEY_ID;
          if (!kmsKeyId) {
            throw new Error('KMS_KEY_ID or AWS_KMS_KEY_ID environment variable is required');
          }

          // Initialize the keystore with the new API
          const keyStore = await createSecretKeyStore(
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
                debug: (msg: string) => logger.debug(msg),
                info: (msg: string) => logger.log(msg),
                warn: (msg: string) => logger.warn(msg),
                error: (msg: string) => logger.error(msg),
              },

              // Attestation (enable in Nitro Enclaves)
              // attestation: {
              //   enabled: true,
              //   required: true,
              //   endpoint: 'http://localhost:8080/attestation',
              // },
            }
          );

          logger.log(`SecretKeyStore initialized with ${keyStore.keys().length} secrets`);
          return keyStore;
        } catch (error) {
          logger.error(`Failed to initialize SecretKeyStore: ${error}`);
          throw error;
        }
      },
    },
  ],
  exports: [KEYSTORE_TOKEN],
})
export class KeyStoreModule {}

