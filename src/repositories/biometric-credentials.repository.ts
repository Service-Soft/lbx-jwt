import { inject } from '@loopback/core';
import { DefaultCrudRepository, juggler } from '@loopback/repository';

import { LbxJwtBindings } from '../keys';
import { BiometricCredentials, BiometricCredentialsRelations } from '../models';

export class BiometricCredentialsRepository extends DefaultCrudRepository<
    BiometricCredentials,
    typeof BiometricCredentials.prototype.id,
    BiometricCredentialsRelations
> {
    constructor(
        @inject(LbxJwtBindings.DATASOURCE_KEY)
        dataSource: juggler.DataSource
    ) {
        super(BiometricCredentials, dataSource);
    }
}