import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const port = process.env.PORT || 3000;
  await app.listen(port);

  console.log(`🚀 NestJS app running on http://localhost:${port}`);
  console.log(`📋 API endpoints:`);
  console.log(`   GET  /           - Health check`);
  console.log(`   GET  /secrets    - List available secret keys`);
  console.log(`   GET  /secrets/:key - Get a specific secret (masked)`);
}

bootstrap();

