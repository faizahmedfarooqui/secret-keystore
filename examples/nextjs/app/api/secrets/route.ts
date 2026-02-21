import { NextResponse } from 'next/server';
import { getKeyStore } from '@/lib/keystore';

export async function GET() {
  try {
    const keyStore = await getKeyStore();

    return NextResponse.json({
      success: true,
      count: keyStore.keys().length,
      keys: keyStore.keys(),
      message: 'These are the available secret keys. Values are never exposed.',
    });
  } catch (error) {
    console.error('Failed to get keystore:', error);
    return NextResponse.json(
      { success: false, error: 'Failed to access keystore' },
      { status: 500 },
    );
  }
}

