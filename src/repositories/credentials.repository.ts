import { inject } from '@loopback/core';
import { DefaultCrudRepository, juggler } from '@loopback/repository';

import { LbxJwtBindings } from '../keys';
import { Credentials, CredentialsRelations } from '../models';

export class CredentialsRepository extends DefaultCrudRepository<
    Credentials,
    typeof Credentials.prototype.id,
    CredentialsRelations
> {
    constructor(
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        dataSource: juggler.DataSource
    ) {
        super(Credentials, dataSource);
    }
}