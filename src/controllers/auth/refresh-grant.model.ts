import { Model, model, property } from '@loopback/repository';

/**
 * Describes the type of grant object taken in by method "refresh".
 */
@model()
export class RefreshGrant extends Model {
    /**
     * The refresh token value.
     */
    @property({
        type: 'string',
        required: true
    })
    refreshToken: string;
}