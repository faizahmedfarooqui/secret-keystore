# NestJS Secret Keystore Example

A complete NestJS application demonstrating `@faizahmedfarooqui/secret-keystore` integration with the new content-based API.

## Prerequisites

- Node.js >= 18.0.0
- AWS Account with KMS key created
- AWS credentials configured (IAM role recommended, or access keys for local dev)

## Local Development Setup

### 1. Install the parent package first

```bash
# From the repository root
npm install
```

### 2. Install example dependencies

```bash
cd examples/nestjs
npm install
```

### 3. Configure environment

```bash
# Copy the example env file
cp .env.example .env
```

### 4. Update your AWS KMS Key

Edit `.env` and replace the placeholder with your actual KMS key ARN:

```bash
# .env
KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/your-actual-key-id
AWS_REGION=us-east-1

# Your secrets (plain text before encryption)
API_KEY=sk-1234567890abcdef
JWT_SECRET=my-super-secret-jwt-key
WEBHOOK_SECRET=whsec_abcdef123456

# Optional: For local dev without IAM roles
# AWS_ACCESS_KEY_ID=your-access-key
# AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 5. Export KMS_KEY_ID and encrypt your secrets

```bash
# Export the KMS key ID (required for encryption)
export KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-actual-key-id"

# Encrypt using IAM role (production)
npm run encrypt:keys

# Or encrypt using explicit credentials (local dev)
npm run encrypt:local
```

After encryption, your `.env` will look like:

```bash
KMS_KEY_ID=arn:aws:kms:...      # Never encrypted
AWS_REGION=us-east-1            # Never encrypted
API_KEY=ENC[AQICAHh...]         # Encrypted!
JWT_SECRET=ENC[AQICAHh...]      # Encrypted!
WEBHOOK_SECRET=ENC[AQICAHh...]  # Encrypted!
```

### 6. Run the application

```bash
# Development mode
npm run start:dev
```

### 7. Test the API

```bash
# Health check
curl http://localhost:3000/

# List available secrets
curl http://localhost:3000/secrets

# Check a specific secret (masked)
curl http://localhost:3000/secrets/API_KEY
```

## Project Structure

```
nestjs/
├── src/
│   ├── main.ts                 # Application entry point
│   ├── app.module.ts           # Root module
│   ├── app.controller.ts       # Health check endpoint
│   ├── keystore/
│   │   └── keystore.module.ts  # Global keystore module (new API)
│   └── secrets/
│       └── secrets.controller.ts # Secrets API endpoints
├── .env.example                # Example environment file
├── package.json
├── tsconfig.json
└── nest-cli.json
```

## How It Works

1. **Content Loading**: `.env` file content is read at startup
2. **KMS Key**: KMS Key ID is provided explicitly (not read from content)
3. **KMS Decryption**: Encrypted values (`ENC[...]`) are decrypted using AWS KMS
4. **Secure Storage**: Decrypted values stored in memory with AES-256-GCM
5. **Dependency Injection**: Inject `KEYSTORE_TOKEN` in any service/controller
6. **Runtime Access**: Call `keyStore.get('KEY_NAME')` to retrieve values

## New API Usage

The keystore now uses a content-based API:

```typescript
import { createSecretKeyStore } from '@faizahmedfarooqui/secret-keystore';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Read file content yourself
const envPath = path.resolve(process.cwd(), '.env');
const content = fs.readFileSync(envPath, 'utf-8');
const kmsKeyId = process.env.KMS_KEY_ID!;

// Pass content + kmsKeyId + options
const keyStore = await createSecretKeyStore(
  { type: 'env', content },
  kmsKeyId,
  {
    paths: ['API_KEY', 'JWT_SECRET', 'WEBHOOK_SECRET'],
    aws: { region: 'us-east-1' },
    security: { inMemoryEncryption: true },
  }
);

const apiKey = keyStore.get('API_KEY');
```

## Enabling Attestation (Nitro Enclaves)

For maximum security in AWS Nitro Enclaves, enable attestation:

```typescript
const keyStore = await createSecretKeyStore(
  { type: 'env', content },
  kmsKeyId,
  {
    paths: ['API_KEY', 'JWT_SECRET'],
    attestation: {
      enabled: true,
      required: true,
      endpoint: 'http://localhost:8080/attestation',
    },
  }
);
```

The library handles the full attestation lifecycle:
- Generates ephemeral RSA-4096 key pairs
- Fetches attestation documents
- Unwraps CMS EnvelopedData from KMS
- Auto-refreshes on 5-minute expiry

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| GET | `/secrets` | List available secret keys |
| GET | `/secrets/:key` | Check if secret exists (shows masked value) |

## NPM Scripts

| Script | Description |
|--------|-------------|
| `npm run start:dev` | Run in development mode with hot reload |
| `npm run encrypt:keys` | Encrypt secrets using IAM role |
| `npm run encrypt:local` | Encrypt secrets using explicit credentials |

## Docker

### Build and Run

```bash
# Build the Docker image
docker build -t nestjs-keystore-example .

# Run the container
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  nestjs-keystore-example
```

### Production with AWS IAM Role

When running on AWS (ECS, EKS, EC2), the container automatically uses the attached IAM role:

```bash
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  nestjs-keystore-example
```

### Local Development with Credentials

For local Docker testing:

```bash
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  -e AWS_ACCESS_KEY_ID="your-access-key" \
  -e AWS_SECRET_ACCESS_KEY="your-secret-key" \
  -v $(pwd)/.env:/app/.env:ro \
  nestjs-keystore-example
```

### Notes

- The `.env` file with encrypted secrets should be included in the image or mounted as a volume
- In production, use AWS Secrets Manager or mount secrets securely
- The container runs as non-root user `nestjs` for security

## Security Notes

- Secrets are **never** exposed in API responses
- Only masked previews are shown for debugging
- Uses **IAM roles by default** for AWS authentication
- Decrypted secrets **never** touch `process.env`
- In-memory values protected with AES-256-GCM
- Secure wipe on `destroy()`
