import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { KeyStoreModule } from './keystore/keystore.module';
import { AppController } from './app.controller';
import { SecretsController } from './secrets/secrets.controller';

@Module({
  imports: [
    // Load .env file
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // Initialize the secure keystore
    KeyStoreModule,
  ],
  controllers: [AppController, SecretsController],
})
export class AppModule {}

