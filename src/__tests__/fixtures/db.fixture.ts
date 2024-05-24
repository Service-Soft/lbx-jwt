
import { inject, lifeCycleObserver, LifeCycleObserver } from '@loopback/core';
import { juggler } from '@loopback/repository';

const config: object = {
    name: 'db',
    connector: 'mysql',
    url: '',
    host: '127.0.0.1',
    port: 3306,
    user: 'lbx_jwt_user',
    password: 'lbx_jwt_password',
    database: 'lbx_jwt'
};

/**
 * Connection to a mysql database.
 */
@lifeCycleObserver('datasource')
export class DbDataSource extends juggler.DataSource implements LifeCycleObserver {
    /**
     * The name of the datasource.
     * Needed by loopback internally.
     */
    static dataSourceName: string = 'db';
    /**
     * The default configuration to use when nothing was provided.
     */
    static readonly defaultConfig: object = config;

    constructor(
        @inject('datasources.config.db', { optional: true })
        dsConfig: object = config
    ) {
        super(dsConfig);
    }
}

/**
 * Database used for testing. This is a mysql connection to test transactions.
 */
// const mysqlTestDb: DbDataSource = new DbDataSource();

/**
 * Database used for testing.  This is a in memory connection to use in cicd.
 */
const inMemoryTestDb: juggler.DataSource = new juggler.DataSource({
    name: 'db',
    connector: 'memory'
});
inMemoryTestDb.beginTransaction = async () => {
    return {
        commit: () => {},
        rollback: () => {}
    };
};

/**
 * Database used for testing.
 */
export const testDb: juggler.DataSource = inMemoryTestDb;