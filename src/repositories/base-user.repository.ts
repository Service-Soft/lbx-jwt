import { Getter, inject } from '@loopback/core';
import { DefaultCrudRepository, HasManyRepositoryFactory, HasOneRepositoryFactory, juggler, repository } from '@loopback/repository';

import { BiometricCredentialsRepository } from './biometric-credentials.repository';
import { CredentialsRepository } from './credentials.repository';
import { LbxJwtBindings } from '../keys';
import { BaseUser, Credentials, BaseUserRelations, BiometricCredentials } from '../models';

export class BaseUserRepository<RoleType extends string> extends DefaultCrudRepository<
    BaseUser<RoleType>,
    typeof BaseUser.prototype.id,
    BaseUserRelations
> {
    readonly credentials: HasOneRepositoryFactory<Credentials, typeof BaseUser.prototype.id>;
    readonly biometricCredentials: HasManyRepositoryFactory<BiometricCredentials, typeof BaseUser.prototype.id>;

    constructor(
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        dataSource: juggler.DataSource,
        @repository.getter('CredentialsRepository')
        protected credentialsRepositoryGetter: Getter<CredentialsRepository>,
        @repository.getter('BiometricCredentialsRepository')
        protected biometricCredentialsRepositoryGetter: Getter<BiometricCredentialsRepository>
    ) {
        super(BaseUser, dataSource);
        this.credentials = this.createHasOneRepositoryFactoryFor('credentials', credentialsRepositoryGetter);
        this.registerInclusionResolver('credentials', this.credentials.inclusionResolver);
        this.biometricCredentials = this.createHasManyRepositoryFactoryFor('biometricCredentials', biometricCredentialsRepositoryGetter);
        this.registerInclusionResolver('biometricCredentials', this.biometricCredentials.inclusionResolver);
    }
}