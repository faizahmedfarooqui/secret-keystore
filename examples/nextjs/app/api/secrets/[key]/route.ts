import { NextRequest, NextResponse } from 'next/server';
import { getKeyStore } from '@/lib/keystore';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ key: string }> },
) {
  try {
    const keyStore = await getKeyStore();
    const { key } = await params;
    const exists = keyStore.has(key);

    if (!exists) {
      return NextResponse.json({
        success: false,
        key,
        exists: false,
        message: `Secret '${key}' not found in keystore`,
      });
    }

    const value = keyStore.get(key);
    const masked = value
      ? `${value.substring(0, 4)}${'*'.repeat(Math.min(value.length - 4, 20))}`
      : '';

    return NextResponse.json({
      success: true,
      key,
      exists: true,
      masked,
      length: value?.length || 0,
      message: 'Secret exists. Full value is never exposed via API.',
    });
  } catch (error) {
    console.error('Failed to get secret:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to access keystore' },
      { status: 500 },
    );
  }
}

