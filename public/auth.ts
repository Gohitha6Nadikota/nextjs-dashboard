import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import bcrypt from 'bcrypt';
import { sql } from '@vercel/postgres';
import { z } from 'zod';
import { authConfig } from './auth.config';
import { useRouter } from 'next/router';
import type { User } from '@/app/lib/definitions';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;

          const user = await getUser(email);
          if (!user) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) {
            return user;
          }
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
  // Callback to handle redirection after successful sign-in
  callbacks: {
    async signIn({ user }) {
      if (user) {
        return true; // This ensures that the user is successfully authenticated
      }
      return false;
    },
    async redirect({ baseUrl }) {
      // Redirect to the dashboard after a successful login
      return `${baseUrl}/dashboard`;
    },
  },
});
