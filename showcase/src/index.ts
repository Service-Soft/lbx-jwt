/* eslint-disable no-console */
import { ApplicationConfig, ShowcaseApplication } from './application';

export * from './application';

/**
 * Starts the api.
 *
 * @param options - Configuration options for the api like the port etc.
 */
export async function main(options: ApplicationConfig = {}): Promise<ShowcaseApplication> {
    const app: ShowcaseApplication = new ShowcaseApplication(options);
    await app.boot();
    await app.migrateSchema();
    await app.start();

    const url: string | undefined = app.restServer.url;
    console.log(`Server is running at ${url}`);
    console.log(`Try ${url}/ping`);

    return app;
}

if (require.main === module) {
    // Run the application
    const config: ApplicationConfig = {
        rest: {
            port: +(process.env.PORT ?? 3000),
            host: process.env.HOST,
            // The `gracePeriodForClose` provides a graceful close for http/https
            // servers with keep-alive clients. The default value is `Infinity`
            // (don't force-close). If you want to immediately destroy all sockets
            // upon stop, set its value to `0`.
            // See https://www.npmjs.com/package/stoppable
            gracePeriodForClose: 5000, // 5 seconds
            openApiSpec: {
                // useful when used with OpenAPI-to-GraphQL to locate your application
                setServersFromRequest: true
            }
        }
    };
    main(config).catch(err => {
        console.error('Cannot start the application.', err);
        process.exit(1);
    });
}