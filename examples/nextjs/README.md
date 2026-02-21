# Next.js Secret Keystore Example

A complete Next.js 14 (App Router) application demonstrating `@faizahmedfarooqui/secret-keystore` integration with the new content-based API.

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
cd examples/nextjs
npm install
```

### 3. Configure environment

```bash
# Copy the example env file
cp .env.example .env.local
```

### 4. Update your AWS KMS Key

Edit `.env.local` and replace the placeholder with your actual KMS key ARN:

```bash
# .env.local
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

After encryption, your `.env.local` will look like:

```bash
KMS_KEY_ID=arn:aws:kms:...      # Never encrypted
AWS_REGION=us-east-1            # Never encrypted
API_KEY=ENC[AQICAHh...]         # Encrypted!
JWT_SECRET=ENC[AQICAHh...]      # Encrypted!
WEBHOOK_SECRET=ENC[AQICAHh...]  # Encrypted!
```

### 6. Run the application

```bash
npm run dev
```

### 7. Open in browser

Visit [http://localhost:3000](http://localhost:3000)

## Project Structure

```
nextjs/
├── app/
│   ├── layout.tsx              # Root layout
│   ├── page.tsx                # Home page (Server Component)
│   └── api/
│       └── secrets/
│           ├── route.ts        # GET /api/secrets
│           └── [key]/
│               └── route.ts    # GET /api/secrets/:key
├── lib/
│   └── keystore.ts             # Keystore singleton (new API)
├── .env.local                  # Your secrets (gitignored)
├── package.json
├── tsconfig.json
└── next.config.js
```

## How It Works

1. **Content Loading**: `.env.local` file content is read at startup
2. **KMS Key**: KMS Key ID is provided explicitly (not read from content)
3. **KMS Decryption**: Encrypted values (`ENC[...]`) are decrypted using AWS KMS
4. **Secure Storage**: Decrypted values stored in memory with AES-256-GCM
5. **Server Access**: Only Server Components and API routes can access secrets
6. **Hot Reload Safe**: Singleton pattern persists across Next.js hot reloads

## New API Usage

The keystore now uses a content-based API:

```typescript
import { createSecretKeyStore } from '@faizahmedfarooqui/secret-keystore';
import * as fs from 'node:fs';
import * as path from 'node:path';

// Read file content yourself
const envPath = path.resolve(process.cwd(), '.env.local');
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

## Features Demonstrated

| Feature | File | Description |
|---------|------|-------------|
| Server Component | `app/page.tsx` | Access secrets in React Server Components |
| API Route | `app/api/secrets/route.ts` | List secrets via REST API |
| Dynamic Route | `app/api/secrets/[key]/route.ts` | Check specific secrets |
| Singleton | `lib/keystore.ts` | Hot-reload safe keystore instance |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/secrets` | List all available secret keys |
| GET | `/api/secrets/:key` | Check if secret exists (shows masked value) |

## NPM Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Run in development mode with hot reload |
| `npm run encrypt:keys` | Encrypt secrets using IAM role |
| `npm run encrypt:local` | Encrypt secrets using explicit credentials |

## Docker

### Build and Run

```bash
# Build the Docker image
docker build -t nextjs-keystore-example .

# Run the container
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  nextjs-keystore-example
```

### Production with AWS IAM Role

When running on AWS (ECS, EKS, EC2), the container automatically uses the attached IAM role:

```bash
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  nextjs-keystore-example
```

### Local Development with Credentials

For local Docker testing:

```bash
docker run -p 3000:3000 \
  -e KMS_KEY_ID="arn:aws:kms:us-east-1:123456789:key/your-key-id" \
  -e AWS_REGION="us-east-1" \
  -e AWS_ACCESS_KEY_ID="your-access-key" \
  -e AWS_SECRET_ACCESS_KEY="your-secret-key" \
  -v $(pwd)/.env.local:/app/.env.local:ro \
  nextjs-keystore-example
```

### Notes

- Uses Next.js standalone output for minimal image size (~50MB)
- The `.env.local` file with encrypted secrets should be included or mounted
- In production, use AWS Secrets Manager or mount secrets securely
- The container runs as non-root user `nextjs` for security

## Security Notes

- ✅ Secrets only accessible on the server
- ✅ Never exposed to client-side code
- ✅ Uses **IAM roles by default** for AWS authentication
- ✅ Decrypted secrets **never** touch `process.env`
- ✅ In-memory values protected with AES-256-GCM
- ✅ API only shows masked previews for debugging
- ✅ Secure wipe on `destroy()`
