import { NextRequest, NextResponse } from 'next/server';
import { verifyClerkUser } from '@/lib/clerk-verify';
import sql from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization');
    console.log('[dev-sync-user] Incoming request authHeader:', authHeader ? `${authHeader.slice(0, 20)}... (length: ${authHeader.length})` : 'NONE');
    const clerkUser = await verifyClerkUser();
    console.log('[dev-sync-user] verifyClerkUser result:', clerkUser?.id ? `id=${clerkUser.id}` : 'null');

    let authId = clerkUser?.id;
    let email = clerkUser?.email || '';
    let fullName = `${clerkUser?.given_name || ''} ${clerkUser?.family_name || ''}`.trim();

    if (!authId && authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      const part = token.split('.')[1];
      if (part) {
        try {
          const claims = JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
          if (claims.sub) {
            authId = claims.sub;
            console.log('[dev-sync-user] Recovered authId from Bearer token claims:', authId);
          }
        } catch (e) {
          console.warn('[dev-sync-user] Failed to decode Bearer claims:', e);
        }
      }
    }

    // Always fetch email and name from Clerk API if missing
    if (authId && (!email || !fullName) && process.env.CLERK_SECRET_KEY) {
      try {
        const { createClerkClient } = await import('@clerk/backend');
        const clerk = createClerkClient({ secretKey: process.env.CLERK_SECRET_KEY });
        const cu = await clerk.users.getUser(authId);
        if (!email) email = cu?.emailAddresses?.[0]?.emailAddress || '';
        const nameFromClerk = `${cu?.firstName || ''} ${cu?.lastName || ''}`.trim();
        if (nameFromClerk && (!fullName || fullName === 'Patient')) fullName = nameFromClerk;
      } catch (err: any) {
        console.warn('[dev-sync-user] Could not fetch user from Clerk API:', err?.message || err);
      }
    }

    if (!authId) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    if (!fullName) fullName = 'Patient';

    let [existingUser] = await sql`
      SELECT uid, role, email FROM users WHERE auth_id = ${authId} LIMIT 1
    `;

    // Self-healing: If not found by auth_id, find by email and link auth_id to existing account
    if (!existingUser && email) {
      const [existingEmail] = await sql`
        SELECT uid, role, email FROM users WHERE LOWER(email) = LOWER(${email}) LIMIT 1
      `;

      if (existingEmail) {
        if (existingEmail.role !== 'patient') {
          return NextResponse.json(
            {
              error: 'This account is not registered as a patient and cannot use the patient app.',
              code: 'ROLE_MISMATCH',
            },
            { status: 403 }
          );
        }

        await sql`
          UPDATE users
          SET auth_id = ${authId}, last_login = NOW()
          WHERE uid = ${existingEmail.uid}
        `;
        existingUser = existingEmail;
      }
    }

    // A doctor who opens the patient app is authenticated but belongs on the other
    // portal. Refuse instead of silently downgrading or re-provisioning them.
    if (existingUser && existingUser.role !== 'patient') {
      return NextResponse.json(
        {
          error: 'This account is not registered as a patient and cannot use the patient app.',
          code: 'ROLE_MISMATCH',
        },
        { status: 403 }
      );
    }

    let uid = existingUser?.uid;

    if (!existingUser) {
      // Role is pinned here and cannot be influenced by the caller.
      const [inserted] = await sql`
        INSERT INTO users (auth_id, email, name, role, is_verified, last_login)
        VALUES (
          ${authId},
          ${email},
          ${fullName},
          'patient',
          true,
          NOW()
        )
        RETURNING uid
      `;
      uid = inserted?.uid;

      if (uid) {
        await sql`INSERT INTO patients (uid) VALUES (${uid}) ON CONFLICT DO NOTHING`;
      }
    } else {
      // Backfill email/name if missing
      const updateFields: any = { last_login: new Date().toISOString() };
      if (email && (!existingUser.email || existingUser.email === '')) {
        updateFields.email = email;
      }
      await sql`
        UPDATE users SET 
          last_login = NOW(),
          email = COALESCE(NULLIF(users.email, ''), ${email || null})
        WHERE uid = ${uid}
      `;
      if (uid) {
        await sql`INSERT INTO patients (uid) VALUES (${uid}) ON CONFLICT DO NOTHING`;
      }
    }

    const [patientRow] = uid ? await sql`SELECT pid FROM patients WHERE uid = ${uid}` : [];
    const pid = patientRow?.pid || null;

    return NextResponse.json({ success: true, uid, pid, role: 'patient' });
  } catch (err: any) {
    console.error('[dev-sync-user] 500:', {
      message: err?.message,
      code: err?.code,
      detail: err?.detail,
      constraint: err?.constraint_name ?? err?.constraint,
      table: err?.table_name,
      column: err?.column_name,
    });
    return NextResponse.json({ error: err.message, code: err?.code }, { status: 500 });
  }
}
