import crypto from 'crypto';

import { inject } from '@loopback/core';
import { Options } from '@loopback/repository';
import { HttpErrors, Request } from '@loopback/rest';

import { HiBase32Utilities } from '../encapsulation/hi-base32.utilities';
import { OtpAuthUtilities, OtpTOTP } from '../encapsulation/otp-auth.utilities';
import { LbxJwtBindings } from '../keys';
import { BaseUser, Credentials } from '../models';
import { BaseUserRepository } from '../repositories';

/**
 * Handles everything connected to two factor authentication.
 */
export class TwoFactorService<RoleType extends string> {
    constructor(
        @inject(LbxJwtBindings.FORCE_TWO_FACTOR)
        protected readonly forceTwoFactor: boolean,
        @inject(LbxJwtBindings.BASE_USER_REPOSITORY)
        protected readonly baseUserRepository: BaseUserRepository<RoleType>,
        @inject(LbxJwtBindings.TWO_FACTOR_HEADER)
        protected readonly twoFactorHeader: string,
        @inject(LbxJwtBindings.TWO_FACTOR_LABEL, { optional: true })
        protected readonly twoFactorLabel?: string
    ) { }

    /**
     * Generates a secret and a two factor auth url to use for a qr code.
     * Both values gets saved to the user credentials of the user with the given id.
     * @param userId - The id of the user that wants to activate two factor authentication.
     * @param options - Additional options eg. Transaction.
     * @returns The qr code url.
     */
    async turnOn2FA(userId: string, options?: Options): Promise<string> {
        const user: BaseUser<string> = await this.baseUserRepository.findById(userId);
        if (user.twoFactorEnabled === true) {
            throw new HttpErrors.BadRequest('The requesting user has already configured two factor authentication.');
        }

        const secret: string = this.generateSecret();
        const totp: OtpTOTP = OtpAuthUtilities.createTOTP({
            label: this.twoFactorLabel,
            secret: secret
        });

        await this.baseUserRepository.credentials(userId).patch({
            twoFactorSecret: secret,
            twoFactorAuthUrl: totp.toString()
        }, options);

        return totp.toString();
    }

    /**
     * Confirms the setup of two factor authentication for the user with the given id.
     * @param userId - The id of the user that wants to activate two factor authentication.
     * @param code - The code that is used to confirm that the user has the correct secret setup.
     * @param options - Additional options eg. Transaction.
     */
    async confirmTurnOn2FA(userId: string, code: string, options?: Options): Promise<void> {
        await this.validateCode(userId, code, options);
        await this.baseUserRepository.updateById(userId, { twoFactorEnabled: true }, options);
    }

    /**
     * Turns off 2fa for the user with the given id.
     * @param userId - The id of the user to turn 2fa off for.
     * @param options - Additional options eg. Transaction.
     */
    async turnOff2FA(userId: string, options?: Options): Promise<void> {
        if (this.forceTwoFactor) {
            throw new HttpErrors.BadRequest(`
                2 Factor Authentication is enforced.
                Override LbxJwtBindings.FORCE_TWO_FACTOR if you want to enable turning it off.
            `);
        }
        await this.baseUserRepository.credentials(userId).patch({
            twoFactorSecret: undefined,
            twoFactorAuthUrl: undefined
        }, options);
        await this.baseUserRepository.updateById(userId, { twoFactorEnabled: false }, options);
    }

    /**
     * Extracts a two factor code from the given request by reading the custom header.
     * @param request - The request of which the two factor code should be read.
     * @returns The found two factor code.
     * @throws When the custom header wasn't found, is empty or not 6 digits long.
     */
    extractCodeFromRequest(request: Request): string {
        if (!request.rawHeaders.find(h => h === this.twoFactorHeader)) {
            throw new HttpErrors.Unauthorized(`"${this.twoFactorHeader}" header not found`);
        }
        const code: string | undefined = request.get(this.twoFactorHeader);
        if (!code) {
            throw new HttpErrors.Unauthorized('No two factor code has been provided.');
        }
        if (code.length !== 6) {
            throw new HttpErrors.Unauthorized('The provided two factor code is not 6 digits long.');
        }
        return code;
    }

    /**
     * Validates the given two factor code for the user with the given id.
     * @param userId - The id of the user that tries to do something that requires a 2fa code.
     * @param code - The two factor code to validate.
     * @param options - Additional options eg. Transaction.
     */
    async validateCode(userId: string, code: string, options?: Options): Promise<void> {
        const credentials: Credentials = await this.baseUserRepository.credentials(userId).get(undefined, options);
        const totp: OtpTOTP = OtpAuthUtilities.createTOTP({
            label: this.twoFactorLabel,
            secret: credentials.twoFactorSecret
        });
        if (totp.validate({ token: code }) == undefined) {
            throw new HttpErrors.Unauthorized('The provided two factor code is invalid.');
        }
    }

    private generateSecret(): string {
        const buffer: Buffer = crypto.randomBytes(15);
        const base32: string = HiBase32Utilities
            .encode(buffer)
            .replaceAll('=', '')
            .substring(0, 24);
        return base32;
    }
}