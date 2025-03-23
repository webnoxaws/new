import NextAuth, { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import AppleProvider from "next-auth/providers/apple";
import jwt from "jsonwebtoken";
import type { OAuthConfig } from "next-auth/providers/oauth";
import type { LinkedInProfile } from "next-auth/providers/linkedin";
import { UserController } from "@/modules/controllers/UserController";
import _ from "lodash";

const LinkedinProvider = (
  config: Partial<OAuthConfig<LinkedInProfile>>
): OAuthConfig<LinkedInProfile> => ({
  id: "linkedin",
  name: "LinkedIn",
  type: "oauth",
  client: { token_endpoint_auth_method: "client_secret_post" },
  issuer: "https://www.linkedin.com",
  profile: (profile: LinkedInProfile) => ({
    id: profile.sub,
    name: profile.name,
    email: profile.email,
    image: profile.picture,
  }),
  wellKnown: "https://www.linkedin.com/oauth/.well-known/openid-configuration",
  authorization: {
    params: {
      scope: "openid profile email",
    },
  },
  style: { logo: "/linkedin.svg", bg: "#069", text: "#fff" },
  ...config,
});

const userController = new UserController();

const authOptions: NextAuthOptions = {
  providers: [
    GoogleProvider({
      clientId: process.env.NEXT_PUBLIC_GOOGLE_ID!,
      clientSecret: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_SECRET!,
    }),
    LinkedinProvider({
      clientId: process.env.NEXT_PUBLIC_LINKEDIN_CLIENT_ID!,
      clientSecret: process.env.NEXT_PUBLIC_LINKEDIN_CLIENT_SECRET!,
    }),
    AppleProvider({
      clientId: process.env.APPLE_CLIENT_ID!,
      clientSecret: process.env.NEXT_PUBLIC_APPLE_CLIENT_SECRET!,
    }),

    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {
          label: "Email",
          type: "text",
          placeholder: "john@example.com",
        },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        if (credentials?.email && credentials?.password) {
          try {
            const dbUser = await userController.LoginWithPassword({
              email: credentials?.email!,
              password: credentials?.password!,
            });

            if (!dbUser) throw new Error("Invalid Credential");

            if (dbUser?.isEmailVerified == false) {
              throw new Error("Please verify your email");
            }

            return {
              id: dbUser.id,
              name: dbUser.name,
              email: dbUser.email,
            };
          } catch (error: unknown) {
            if (error instanceof Error) {
              throw new Error(error?.message);
            }
            throw new Error("Something went wrong, please try again");
          }
        }
        return null;
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
  jwt: {
    secret: process.env.NEXTAUTH_JWT_SECRET,
  },
  callbacks: {
    async jwt({ token, account, user }: any) {
      if (account) {
        // console.log("token ", token);
        // console.log("account ", account);
        // console.log("user ", user);

        let userFromDB = await userController.getUserAccount({
          email: user.email,
        });

        if (_.isEmpty(userFromDB)) {
          const password = Math.floor(1000 + Math.random() * 9000);

          userFromDB = await userController.createUserAccount({
            email: user.email,
            name: user.name,
            profile: user.image ?? "",
            role: "USER",
            password: String(password),
          });
        }

        token.accessToken = jwt.sign(
          {
            email: userFromDB.email,
          },
          process.env.NEXTAUTH_SECRET!,
          { expiresIn: "1h" }
        );
        token.profile = userFromDB.profile;
        token.provider = account.provider;
        token.expiration = account.expires_at;
        token.createdAt = Date.now();
      }
      return token;
    },
    async session({ session, token }: any) {
      // Add token data to the session object
      session.accessToken = token.accessToken;
      session.provider = token.provider;
      session.expiration = token.expiration;
      session.createdAt = token.createdAt;
      session.user.image = token.profile;
      return session;
    },
    async redirect({ url, baseUrl }) {
      console.log({ url, baseUrl });
      return url.startsWith(baseUrl) ? url : baseUrl + url;
    },
  },
  pages: {
    signIn: "/auth/signin",
  },
  secret: process.env.NEXTAUTH_SECRET,

  // need to uncomment this for apple auth
  // cookies: {
  //   pkceCodeVerifier: {
  //     name: `next-auth.pkce.code_verifier`,
  //     options: {
  //       httpOnly: true,
  //       sameSite: "none",
  //       path: "/",
  //       secure: true,
  //       maxAge: 60 * 15,
  //     },
  //   },

  // },

  // useSecureCookies: true,
};
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
