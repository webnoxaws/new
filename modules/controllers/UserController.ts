import { NextResponse } from "next/server";
import { IUser } from "../models/User";
import { z, ZodError } from "zod";
import { ResponseGenerator } from "@/utils/responseGenerator";
import { UserValidation } from "../validations/UserValidation";
import { UserService } from "../services/UserService";
import jwt from "jsonwebtoken";

export class UserController {
  userService: UserService;
  Secret;

  constructor() {
    this.userService = new UserService();
    this.Secret = process.env.NEXTAUTH_SECRET;
  }

  async RegisterUser(req: Request) {
    try {
      const body = await req.json();
      const baseUrl = req.headers.get("origin") || "http://localhost:3000";
      
      const { data, success, error } =
        UserValidation.RegisterUser().safeParse(body);

      if (!success) {
        console.log(error.format());
        return NextResponse.json(
          ...ResponseGenerator.generate(
            400,
            null,
            "Bad Request",
            error.format()
          )
        );
      }
      const res = await this.userService.registerUser({
        userData: body,
        baseUrl,
      });

      return NextResponse.json(
        ResponseGenerator.generate(200, res, "User Registred Successfully")
      );
    } catch (error: unknown) {
      return this.handleError(error);
    }
  }

  async LoginWithPassword(credential: Pick<IUser, "email" | "password">) {
    return this.userService.LoginWithPassword({ ...credential });
  }

  async verifyUserAccount(req: Request) {
    try {
      const url = new URL(req.url);
      const token = url.searchParams.get("token");

      if (!token) {
        return NextResponse.json(
          ResponseGenerator.generate(
            400,
            null,
            "Verification token is required"
          )
        );
      }

      const decoded = jwt.verify(token, this.Secret!) as { id: string };
      const result = await this.userService.verifyUserAccount(decoded.id);

      return NextResponse.redirect(
        "http://localhost:3000/auth/verification/success"
      );
    } catch (error) {
      return NextResponse.redirect(
        "http://localhost:3000/auth/verification/invalid"
      );
    }
  }

  async getVerificationToken({ email }: Pick<IUser, "email">) {
    return this.userService.getVerificationToken({ email });
  }

  async createUserAccount(userData: IUser) {
    return await this.userService.createUserAccount(userData);
  }

  async getUserAccount(userData: Pick<IUser, "email" | "id">) {
    return await this.userService.getUserAccount(userData);
  }

  private handleError(error: unknown): NextResponse {
    let errorMessage = "An unknown error occurred";
    if (error instanceof Error) {
      errorMessage = error.message;
    }
    return NextResponse.json(
      ...ResponseGenerator.generate(500, null, errorMessage)
    );
  }
}
