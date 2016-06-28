import { Oauth2Service } from './src/oauth2.service';

export * from './src/oauth2.service';
export * from './src/oauth2.access-token';
export * from './src/oauth2.id-token';
export * from './src/oauth2.oidc-config';
export * from './src/oauth2.auth-http';

export const OAUTH2_PROVIDERS: any[] = [
    Oauth2Service
] ;
