import { BindingScope, bind } from '@loopback/core';
import { BaseBiometricCredentialsService } from 'lbx-jwt';

@bind({ scope: BindingScope.TRANSIENT })
export class BiometricCredentialsService extends BaseBiometricCredentialsService {
    protected readonly RP_NAME: string = 'Test';
    protected readonly RP_DOMAIN: string = 'localhost';

    protected get RP_ORIGIN(): string {
        return `http://${this.RP_DOMAIN}:4200`;
    }
}