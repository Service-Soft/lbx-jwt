import { inject } from '@loopback/core';
import { IsolationLevel, repository } from '@loopback/repository';
import { getModelSchemaRef, post, requestBody } from '@loopback/rest';
import { BaseUser, BaseUserRepository, Credentials, DefaultEntityOmitKeys } from 'lbx-jwt';
import { DbDataSource } from '../datasources';
import { Roles } from '../models/roles.enum';
import { BcryptUtilities } from './bcrypt.utilities';
import { NewUser } from './new-user.model';

/**
 * Controller for registering new users.
 */
export class RegisterController {
    constructor(
        @repository(BaseUserRepository)
        private readonly userRepository: BaseUserRepository<Roles>,
        @inject('datasources.db')
        private readonly dataSource: DbDataSource
    ) {}

    /**
     * Registers a new user.
     *
     * @param newUser - The data from which the user should be created.
     * @returns The newly created user.
     */
    @post('/register', {
        responses: {
            '200': {
                description: 'User',
                content: {
                    'application/json': {
                        schema: getModelSchemaRef(BaseUser<Roles>, {
                            title: 'User',
                            exclude: ['credentials']
                        })
                    }
                }
            }
        }
    })
    async createUser(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(NewUser, {
                        title: 'NewUser',
                        exclude: ['id']
                    })
                }
            }
        })
        newUser: Omit<NewUser, DefaultEntityOmitKeys | 'id'>
    ): Promise<Omit<BaseUser<Roles>, DefaultEntityOmitKeys | 'credentials'>> {
        // eslint-disable-next-line @typescript-eslint/typedef
        const transaction = await this.dataSource.beginTransaction(IsolationLevel.READ_COMMITTED);
        try {
            const baseUser: Omit<BaseUser<Roles>, DefaultEntityOmitKeys | 'credentials' | 'id'> = {
                email: newUser.email,
                roles: [Roles.USER]
            };
            const finishedBaseUser: BaseUser<Roles> = await this.userRepository.create(baseUser, { transaction: transaction });
            const credentials: Omit<Credentials, DefaultEntityOmitKeys | 'id' | 'baseUserId'> = {
                password: await BcryptUtilities.hash(newUser.password)
            };
            await this.userRepository.credentials(finishedBaseUser.id).create(credentials, { transaction: transaction });
            await transaction.commit();
            return {
                id: finishedBaseUser.id,
                email: finishedBaseUser.email,
                roles: finishedBaseUser.roles
            };
        }
        catch (error) {
            await transaction.rollback();
            throw error;
        }
    }
}