// Uncomment these imports to begin using these cool features!

import { authenticate } from '@loopback/authentication';
import { authorize } from '@loopback/authorization';
import { inject } from '@loopback/core';
import { repository } from '@loopback/repository';
import { get, HttpErrors } from '@loopback/rest';
import { SecurityBindings } from '@loopback/security';
import { BaseUser, BaseUserProfile, BaseUserRepository, roleAuthorization } from 'lbx-jwt';
import { Roles } from '../models/roles.enum';

// import {inject} from '@loopback/core';


/**
 * Controller that provides some endpoints to test authentication and authorization.
 */
export class TestController {
    constructor(
        @repository(BaseUserRepository)
        private readonly userRepository: BaseUserRepository<Roles>
    ) {}

    // eslint-disable-next-line jsdoc/require-jsdoc
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

    // eslint-disable-next-line jsdoc/require-jsdoc
    @authenticate('jwt')
    @authorize({ voters: [roleAuthorization], allowedRoles: [Roles.USER] })
    @get('user-data')
    async getUserData(): Promise<string> {
        return 'secret user data';
    }

    // eslint-disable-next-line jsdoc/require-jsdoc
    @authenticate('jwt')
    @authorize({ voters: [roleAuthorization], allowedRoles: [Roles.ADMIN] })
    @get('admin-data')
    async getAdminData(): Promise<string> {
        return 'secret admin data';
    }
}