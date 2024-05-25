import { injectable } from '@loopback/core';
import { asSpecEnhancer, mergeOpenAPISpec, OASEnhancer, OpenApiSpec, ReferenceObject, SecurityRequirementObject, SecuritySchemeObject } from '@loopback/rest';

/**
 * The type for the OpenApi security scheme object.
 */
interface SecuritySchemeObjects {
    [securityScheme: string]: SecuritySchemeObject | ReferenceObject
}

const OPERATION_SECURITY_SPEC: SecurityRequirementObject[] = [
    {
        // secure all endpoints with 'jwt'
        jwt: []
    }
];

const SECURITY_SCHEME_SPEC: SecuritySchemeObjects = {
    jwt: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
    }
};

/**
 * A spec enhancer to add bearer token OpenAPI security entry to
 * `spec.component.securitySchemes`.
 */
@injectable(asSpecEnhancer)
export class SecuritySpecEnhancer implements OASEnhancer {

    /**
     * The name of the enhancer.
     */
    readonly name: string = 'bearerAuth';

    /**
     * Modifies the OpenApi specification.
     * @param spec - The modification done to the OpenApi specification.
     * @returns The modified OpenApi specification.
     */
    modifySpec(spec: OpenApiSpec): OpenApiSpec {
        const patchSpec: Partial<OpenApiSpec> = {
            components: {
                securitySchemes: SECURITY_SCHEME_SPEC
            },
            security: OPERATION_SECURITY_SPEC
        };
        return mergeOpenAPISpec(spec, patchSpec);
    }
}