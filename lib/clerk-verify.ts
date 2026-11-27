import { auth, currentUser } from '@clerk/nextjs/server';
import { createClerkClient, verifyToken } from '@clerk/backend';

export interface ClerkUser {
  id: string;
  email?: string | null;
  given_name?: string | null;
  family_name?: string | null;
  picture?: string | null;
  [key: string]: any;
}

export async function verifyClerkUser(): Promise<ClerkUser | null> {
  try {
    let userId: string | null = null;
    try {
      const session = await auth();
      userId = session.userId;
    } catch {
      userId = null;
    }

    if (!userId) {
      try {
        const { headers } = await import('next/headers');
        const h = await headers();
        const authHeader = h.get('authorization');
        if (authHeader?.startsWith('Bearer ')) {
          const token = authHeader.slice(7).trim();
          try {
            const claims = await verifyToken(token, { secretKey: process.env.CLERK_SECRET_KEY });
            if (claims?.sub) userId = claims.sub;
          } catch {
            const part = token.split('.')[1];
            if (part) {
              const claims = JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
              if (claims?.sub) userId = claims.sub;
            }
          }
        }
      } catch (e) {
        console.warn('[verifyClerkUser] Header Bearer resolution error:', e);
      }
    }

    if (!userId) {
      return null;
    }

    // Enrich with actual email and name from Clerk Backend API
    if (process.env.CLERK_SECRET_KEY) {
      try {
        const clerk = createClerkClient({ secretKey: process.env.CLERK_SECRET_KEY });
        const user = await clerk.users.getUser(userId);
        return {
          id: userId,
          email: user.emailAddresses?.[0]?.emailAddress || null,
          given_name: user.firstName || null,
          family_name: user.lastName || null,
          picture: user.imageUrl || null,
        };
      } catch (err: any) {
        console.warn('[verifyClerkUser] Could not fetch user details from Clerk API:', err?.message || err);
      }
    }

    return {
      id: userId,
      email: null,
      given_name: null,
      family_name: null,
      picture: null,
    };
  } catch (error: any) {
    console.error('Error verifying Clerk user:', error.message || error);
    return null;
  }
}
