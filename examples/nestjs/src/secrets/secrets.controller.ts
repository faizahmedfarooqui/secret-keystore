import { Controller, Get, Param, Inject } from '@nestjs/common';
import { SecretKeyStore } from '@faizahmedfarooqui/secret-keystore';
import { KEYSTORE_TOKEN } from '../keystore/keystore.module';

@Controller('secrets')
export class SecretsController {
  constructor(
    @Inject(KEYSTORE_TOKEN)
    private readonly keyStore: SecretKeyStore,
  ) {}

  /**
   * GET /secrets
   * List all available secret keys (not values!)
   */
  @Get()
  listSecrets() {
    return {
      count: this.keyStore.keys().length,
      keys: this.keyStore.keys(),
      message: 'These are the available secret keys. Values are never exposed via API.',
    };
  }

  /**
   * GET /secrets/:key
   * Check if a secret exists and show masked value
   */
  @Get(':key')
  getSecret(@Param('key') key: string) {
    const exists = this.keyStore.has(key);

    if (!exists) {
      return {
        key,
        exists: false,
        message: `Secret '${key}' not found in keystore`,
      };
    }

    const value = this.keyStore.get(key);
    const masked = value ? `${value.substring(0, 4)}${'*'.repeat(Math.min(value.length - 4, 20))}` : '';

    return {
      key,
      exists: true,
      masked,
      length: value?.length || 0,
      message: 'Secret exists. Full value is never exposed via API.',
    };
  }
}

