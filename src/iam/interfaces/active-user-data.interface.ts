import { Role } from "@prisma/client";

export interface ActiveUserData {

    sub: number;

    email: string;

    role: Role;
}