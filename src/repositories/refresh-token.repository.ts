import { inject } from '@loopback/core';
import { DefaultCrudRepository, juggler } from '@loopback/repository';
import { LbxJwtBindings } from '../keys';
import { RefreshToken, RefreshTokenRelations } from '../models';

export class RefreshTokenRepository extends DefaultCrudRepository<
    RefreshToken,
    typeof RefreshToken.prototype.id,
    RefreshTokenRelations
> {
    constructor(
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        dataSource: juggler.DataSource
    ) {
        super(RefreshToken, dataSource);
    }
}