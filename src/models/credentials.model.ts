import { Entity, model, property } from '@loopback/repository';

/**
 * The credentials of an user.
 * They are stored separately so its less likely there are sent to the frontend by accident.
 */
@model()
export class Credentials extends Entity {

    /**
     * The id of the credentials.
     */
    @property({
        type: 'string',
        required: true,
        defaultFn: 'uuidv4',
        id: true
    })
    id: string;

    /**
     * The password of the user.
     * Is stored as a hashed string.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            minLength: 12
        }
    })
    password: string;

    /**
     * The user that this credentials belong to.
     */
    @property({
        type: 'string',
        required: true
    })
    baseUserId: string;

    constructor(data?: Partial<Credentials>) {
        super(data);
    }
}

/**
 * Properties of the entity relations.
 */
export interface CredentialsRelations {
    // describe navigational properties here
}

/**
 * The entity with its relation properties.
 */
export type CredentialsWithRelations = Credentials & CredentialsRelations;