import { Entity, model, property } from '@loopback/repository';

/**
 * The model for a new user request.
 */
@model()
export class NewUser extends Entity {
    /**
     * The id of the user.
     */
    @property({
        type: 'string',
        required: true,
        defaultFn: 'uuidv4',
        id: true
    })
    id: string;

    /**
     * The email of the user.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            format: 'email'
        }
    })
    email: string;
    /**
     * The password of the user.
     */
    @property({
        type: 'string',
        required: true,
        jsonSchema: {
            minLength: 12
        }
    })
    password: string;
}

/**
 * Properties of the entity relations.
 */
export interface NewUserRelations {
    // describe navigational properties here
}

/**
 * Properties of the entity relations.
 */
export type NewUserWithRelations = NewUser & NewUserRelations;