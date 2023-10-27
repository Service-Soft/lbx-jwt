import { compare, genSalt, hash } from 'bcryptjs';

/**
 * Encapsulates functionality of the bcryptjs package.
 */
export abstract class BcryptUtilities {
    /**
     * Asynchronously compares the given data against the given hash.
     * @param s - Data to compare.
     * @param hash - Data to be compared to.
     * @returns Promise, if callback has been omitted.
     */
    static async compare(s: string, hash: string): Promise<boolean> {
        return compare(s, hash);
    }

    /**
     * Asynchronously generates a hash for the given string.
     * @param value - The value that should be hashed.
     * @returns A hash of the given value.
     */
    static async hash(value: string): Promise<string> {
        return hash(value, await genSalt());
    }
}