import { promisify } from "util";
import { scrypt, randomBytes } from "crypto";

const scryptAsync = promisify(scrypt);

export class Password {
  static async toHash(password: string) {
    const salt = randomBytes(8).toString("hex");
    const buffer = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${buffer.toString("hex")}.${salt}`;
  }

  static async compare(stored: string, supplied: string) {
    const [hashedPass, salt] = stored.split(".");
    const buffer = (await scryptAsync(supplied, salt, 64)) as Buffer;

    return buffer.toString("hex") === hashedPass;
  }
}
