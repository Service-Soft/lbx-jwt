import { authenticate } from '@loopback/authentication';
import { authorize } from '@loopback/authorization';
import { inject } from '@loopback/core';
import { repository } from '@loopback/repository';
import { del, get, HttpErrors } from '@loopback/rest';
import { SecurityBindings } from '@loopback/security';
import { BaseUser, BaseUserProfile, BaseUserRepository, roleAuthorization } from 'lbx-jwt';
import { Roles } from '../models/roles.enum';

/**
 * Controller that provides some endpoints to test authentication and authorization.
 */
export class TestController {
    constructor(
        @repository(BaseUserRepository)
        private readonly userRepository: BaseUserRepository<Roles>
    ) { }

    @authenticate('jwt')
    @get('me')
    async getCurrentUser(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<Roles>
    ): Promise<BaseUser<Roles>> {
        const foundUser: BaseUser<Roles> | null = await this.userRepository.findOne({ where: { id: userProfile.id } });
        if (!foundUser) {
            throw new HttpErrors.NotFound();
        }
        return foundUser;
    }

    @authenticate('jwt')
    @authorize({ voters: [roleAuthorization], allowedRoles: [Roles.USER] })
    @get('user-data')
    async getUserData(): Promise<string> {
        return 'secret user data';
    }

    @authenticate('jwt')
    @authorize({ voters: [roleAuthorization], allowedRoles: [Roles.ADMIN] })
    @get('admin-data')
    async getAdminData(): Promise<string> {
        return 'secret admin data';
    }

    @authenticate('jwt')
    @del('/all-biometric-credentials')
    async deleteAll(
        @inject(SecurityBindings.USER)
        userProfile: BaseUserProfile<Roles>
    ): Promise<void> {
        await this.userRepository.biometricCredentials(userProfile.id).delete();
    }
}