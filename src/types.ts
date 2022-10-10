
/**
 * Some default keys that are often omitted when dealing with entities.
 */
export type DefaultEntityOmitKeys = 'getId' | 'getIdObject' | 'toJSON' | 'toObject';

/**
 * Describes the token object that returned by the refresh token service functions.
 */
export type TokenObject = {
    /**
     * The access token used to authenticate requests.
     */
    accessToken: string,
    /**
     * The new refresh token that is used whenever a new access token is required.
     */
    refreshToken: string
};