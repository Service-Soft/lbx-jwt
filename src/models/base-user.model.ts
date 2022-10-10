import { inject } from '@loopback/core';
import { Entity, hasOne, model, property } from '@loopback/repository';
import { LbxJwtBindings } from '../keys';
import { Credentials } from './credentials.model';

/**
 * The base user model with data that all user types share.
 */
@model()
export class BaseUser<RoleType extends string> extends Entity {

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
     * Needs to be unique and in a valid format.
     */
    @property({
        type: 'string',
        required: true,
        index: { unique: true },
        jsonSchema: {
            format: 'email'
        }
    })
    email: string;

    /**
     * The roles the user has.
     * Is used by authorization.
     */
    @property({
        type: 'array',
        itemType: 'string',
        required: true
        // json schema restricting to certain roles is set in constructor.
    })
    roles: RoleType[];

    /**
     * The credentials of the user.
     * Contains the hashed password.
     */
    @hasOne(() => Credentials)
    credentials: Credentials;

    /**
     * Helper for defining the roles open api.
     */
    @inject(LbxJwtBindings.ROLES)
    private readonly roleValues: RoleType[];

    constructor(data?: Partial<BaseUser<RoleType>>) {
        super(data);
        BaseUser.definition.properties['roles'].jsonSchema = {
            items: {
                enum: this.roleValues
            }
        };
    }
}

/**
 * Properties of the entity relations.
 */
export interface BaseUserRelations {
    // describe navigational properties here
}

/**
 * The entity with its relation properties.
 */
export type BaseUserWithRelations<RoleType extends string> = BaseUser<RoleType> & BaseUserRelations;