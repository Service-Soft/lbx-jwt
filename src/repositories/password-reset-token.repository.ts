import { inject, Getter } from '@loopback/core';
import { DefaultCrudRepository, repository, BelongsToAccessor, juggler } from '@loopback/repository';
import { LbxJwtBindings } from '../keys';
import { BaseUser } from '../models';
import { PasswordResetToken, PasswordResetTokenRelations } from '../models/password-reset-token.model';
import { BaseUserRepository } from './base-user.repository';

export class PasswordResetTokenRepository<RoleType extends string> extends DefaultCrudRepository<
    PasswordResetToken,
    typeof PasswordResetToken.prototype.id,
    PasswordResetTokenRelations
> {

    readonly baseUser: BelongsToAccessor<BaseUser<RoleType>, typeof PasswordResetToken.prototype.id>;

    constructor(
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        dataSource: juggler.DataSource,
        @repository.getter('BaseUserRepository')
        protected baseUserRepositoryGetter: Getter<BaseUserRepository<RoleType>>
    ) {
        super(PasswordResetToken, dataSource);
        this.baseUser = this.createBelongsToAccessorFor('baseUser', baseUserRepositoryGetter);
        this.registerInclusionResolver('baseUser', this.baseUser.inclusionResolver);
    }
}