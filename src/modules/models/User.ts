export interface IUser {
  id?: string;
  name: string;
  email: string;
  profile?: string | null;
  emailVerifiedAt?: Date | null;
  isEmailVerified?: Boolean | null;
  password: string;
  role: "USER" | "ADMIN";
}

export class User implements IUser {
  id?: string | undefined;
  name: string;
  email: string;
  profile?: string;
  emailVerifiedAt?: Date | undefined | null;
  isEmailVerified?: Boolean | undefined | null;
  password: string;
  role: "USER" | "ADMIN";

  constructor(data: IUser) {
    const {
      id,
      name,
      email,
      emailVerifiedAt,
      isEmailVerified,
      password,
      role,
      profile,
    } = data;
    this.id = id;
    this.name = name;
    this.email = email;
    this.emailVerifiedAt = emailVerifiedAt;
    this.isEmailVerified = isEmailVerified;
    this.password = password;
    this.role = role;
    this.profile = role ?? null;
  }
}
