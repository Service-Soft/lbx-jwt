import { securityId } from '@loopback/security';
import { BaseUserProfile } from '../../models';
import { AccessTokenService } from '../../services';
import { expect } from '@loopback/testlab';
import { sleep } from '../fixtures/helpers';
import { HttpErrors } from '@loopback/rest';

const USER_PROFILE: BaseUserProfile<string> = {
    id: '1',
    email: 'test@email.com',
    [securityId]: '1',
    roles: ['user']
};
const DECODED_USER_PROFILE: unknown = {
    id: '1',
    name: '',
    roles: ['user']
};

const ACCESS_TOKEN_SECRET: string = 'accessTokenSecret';
const ACCESS_TOKEN_EXPIRES_IN__MS: number = 300000;

const accessTokenService: AccessTokenService<string> = new AccessTokenService(ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRES_IN__MS);

describe('AccessTokenService', () => {
    it('generateToken', async () => {
        const accessToken: string = await accessTokenService.generateToken(USER_PROFILE);
        expect(accessToken).to.not.be.empty();

        await sleep(1000); // Is needed for the jwt to be different.

        const accessTokenTwo: string = await accessTokenService.generateToken(USER_PROFILE);
        expect(accessToken).to.not.equal(accessTokenTwo);
    });

    it('verifyToken', async () => {
        const accessToken: string = await accessTokenService.generateToken(USER_PROFILE);
        const userProfileFromToken: BaseUserProfile<string> = await accessTokenService.verifyToken(accessToken);
        expect(userProfileFromToken).to.deepEqual(DECODED_USER_PROFILE);

        const expectedError: HttpErrors.HttpError<401> = new HttpErrors.Unauthorized('Error verifying token: invalid token');
        const invalidToken: string = 'aaa.bbb.ccc';
        await expect(accessTokenService.verifyToken(invalidToken)).to.be.rejectedWith(expectedError);
    });
});