// modules/product/ProductService.ts

import _ from "lodash";
import { IUser, User } from "../models/User";
import db from "../../lib/db";
import jwt from "jsonwebtoken";
import { mail } from "@/lib/mail";
import { AccountVerificationTemplate } from "@/lib/mail/templates";

export class UserService {
  Secret;

  constructor() {
    this.Secret = process.env.NEXTAUTH_SECRET;
  }

  async registerUser({
    userData,
    baseUrl,
  }: {
    userData: IUser;
    baseUrl: string;
  }): Promise<IUser | null> {
    try {
      const user = new User(userData);

      const existingUser = await db.user.findFirst({
        where: { email: user.email },
      });

      if (existingUser) {
        throw new Error("User with this email already exists");
      }

      const requestData = await db.regstrationRequest.create({
        data: {
          email: user.email,
          name: user.name,
          password: user.password,
          role: "USER",
        },
      });

      const token = jwt.sign({ id: requestData?.id }, this.Secret!);

      await mail.sendMail({
        to: user.email,
        subject: "Account Verification Mail",
        template: AccountVerificationTemplate({
          link: `${baseUrl}/api/auth/verification?token=${token}`,
        }),
      });
      return requestData;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async LoginWithPassword(userData: Pick<IUser, "email" | "password">) {
    let user;
    try {
      user = await db.user.findFirst({
        where: { email: userData.email, password: userData.password },
      });

      if (_.isEmpty(user))
        user = db.regstrationRequest.findFirst({
          where: {
            email: userData.email,
            password: userData.password,
          },
        });

      console.log("Payload : ", userData);
      console.log("User from db : ", user);
      // return user || null;
    } catch (error) {
      console.log(error);
    }
    return user;
  }

  async verifyUserAccount(registrationRequestId: string): Promise<string> {
    try {
      const registrationRequest = await db.regstrationRequest.findUnique({
        where: { id: registrationRequestId },
      });

      if (!registrationRequest) {
        throw new Error("Invalid verification token");
      }

      const existingUser = await db.user.findUnique({
        where: { email: registrationRequest.email },
      });

      if (existingUser) {
        throw new Error("User with this email already exists");
      }

      const user = await db.user.create({
        data: {
          email: registrationRequest.email,
          name: registrationRequest.name,
          password: registrationRequest.password,
          role: registrationRequest.role,
          isEmailVerified: true,
        },
      });

      await db.regstrationRequest.delete({
        where: { id: registrationRequestId },
      });

      return "Account verified successfully";
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(error.message);
      }
      throw new Error("Error verifying account");
    }
  }

  async getVerificationToken({ email }: Pick<IUser, "email">) {
    try {
      const existingUser = await db.user.findFirst({
        where: { email },
      });

      if (existingUser) {
        throw new Error("User with this email already exists");
      }

      const requestData = await db.regstrationRequest.findFirst({
        where: {
          email,
        },
      });

      if (_.isEmpty(requestData)) return null;

      const token = jwt.sign({ id: requestData?.id }, this.Secret!);

      return token;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async createUserAccount(userData: IUser): Promise<IUser> {
    try {
      const user = new User(userData);
     

      const existingUser = await db.user.findFirst({
        where: { email: user.email },
      });

      if (existingUser) {
        throw new Error("User with this email already exists");
      }

      const requestData = await db.user.create({
        data: {
          email: user.email,
          name: user.name,
          profile: userData.profile,
          password: String(userData.password),
          role: "USER",
          isEmailVerified: true,
          emailVerifiedAt: new Date(),
        },
      });

      return requestData;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  async getUserAccount(
    userData: Pick<IUser, "email" | "id">
  ): Promise<IUser | null> {
    const user = await db.user.findUnique({
      where: {
        email: userData.email,
        ...(userData.id && { id: userData.id }),
      },
    });

    return user;
  }
}
