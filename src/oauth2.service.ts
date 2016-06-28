import { Injectable, EventEmitter} from '@angular/core';
import { Http } from '@angular/http';


import { Oauth2AccessToken } from './oauth2.access-token';
import { Oauth2OidcConfig } from './oauth2.oidc-config' ;
import { Oauth2IdToken } from './oauth2.id-token';
import { Oauth2Storage } from './oauth2.storage';
import { Oauth2Profile } from './oauth2.profile';
import { Oauth2AuthHttp } from './oauth2.auth-http';

export interface Oauth2EmptyEvent {};
export interface Oauth2TokenEvent {
    token: any;
};
export interface Oauth2ProfileEvent {
    profile: any;
};
export interface Oauth2ConfigEvent {
    config: any;
};
export interface Oauth2ErrorEvent {
    error: any;
    error_description: any;
};

export interface Window {
    hextob64u(s: string): string;
}

@Injectable()
export class Oauth2Service {


    public static STORAGE_KEY_TOKEN = 'oauth2_token';
    public static STORAGE_KEY_OIDC_CONFIG = 'oauth2_oidc_config';
    public static STORAGE_KEY_PROFILE = 'oauth2_profile';

    // When methods login() or logout() are triggered
    public static Login: EventEmitter<Oauth2EmptyEvent> = new EventEmitter<Oauth2EmptyEvent>();
    public static Logout: EventEmitter<Oauth2EmptyEvent> = new EventEmitter<Oauth2EmptyEvent>();

    // On successful login
    public static LoggedIn: EventEmitter<Oauth2TokenEvent> = new EventEmitter<Oauth2TokenEvent>();

    // On valid credentials (recovered from session or successful login)
    public static Authorized: EventEmitter<Oauth2TokenEvent> = new EventEmitter<Oauth2TokenEvent>();

    // On error when logging
    public static LoginError: EventEmitter<Oauth2ErrorEvent> = new EventEmitter<Oauth2ErrorEvent>();

    // On detection of user not logged in (expired, no token found, ...)
    public static LoggedOut: EventEmitter<Oauth2EmptyEvent> = new EventEmitter<Oauth2EmptyEvent>();

    // When token expires, thi event is fired before LoggedOut event
    public static TokenExpired: EventEmitter<Oauth2EmptyEvent> = new EventEmitter<Oauth2EmptyEvent>();

    // When token is destroyed
    public static TokenDestroyed: EventEmitter<Oauth2EmptyEvent> = new EventEmitter<Oauth2EmptyEvent>();
    public static TokenDestroyError: EventEmitter<Oauth2ErrorEvent> = new EventEmitter<Oauth2ErrorEvent>();

    // When profile is loaded
    public static Profile: EventEmitter<Oauth2ProfileEvent> = new EventEmitter<Oauth2ProfileEvent>();
    // On error when loading profile
    public static ProfileError: EventEmitter<Oauth2ErrorEvent> = new EventEmitter<Oauth2ErrorEvent>();

    // When OIDC config is loaded
    public static OIDCConfig: EventEmitter<Oauth2ConfigEvent> = new EventEmitter<Oauth2ConfigEvent>();
    public static OIDCKeys: EventEmitter<Oauth2ConfigEvent> = new EventEmitter<Oauth2ConfigEvent>();

    // On error when loading config
    public static OIDCConfigError: EventEmitter<Oauth2ErrorEvent> = new EventEmitter<Oauth2ErrorEvent>();
    // On error when loading keys
    public static OIDCKeysError: EventEmitter<Oauth2ErrorEvent> = new EventEmitter<Oauth2ErrorEvent>();



    private static storage: Oauth2Storage;

    public profile: {};

    private defaultConfig: any = {
        site: undefined,
        redirectUri: undefined,
        clientId: undefined,
        authorizePath: '/oauth/authorize',
        tokenPath: '/oauth/token',
        responseType: 'token',
        storage: sessionStorage,
        scope: 'profile',
        profileUri: undefined,
        generateState: false,
        useNonce: false,
        issuer: undefined,
        subject: undefined,
        wellKnown: false,
        checkAtHash: true,
        logOutPath: undefined,
        state: undefined,
        nonce: undefined,
        destroyTokenPath: undefined
    };

    private currentConfig = this.defaultConfig;
    private initialized = false;
    private idToken: Oauth2IdToken;
    private accessToken: Oauth2AccessToken;
    private oidcConfig: Oauth2OidcConfig;
    private oauthProfile: Oauth2Profile;
    private authHttp: Oauth2AuthHttp;

    public static getStorage() {
        return Oauth2Service.storage;
    }

    constructor(
        private window: Window,
        private location: Location,
        private http: Http) {
    }

    public getCurrentConfig() {
        return this.currentConfig;
    }

    public init(config: any) {
        // Check if required elements have been passed
        let requiredParams = ['site', 'clientId', 'redirectUri'];
        for (let p in requiredParams) {
            if (typeof config[p] === undefined) {
                throw new Error('Missing config parameter ' + p);
            }
        }

        this.currentConfig = Object.assign(this.currentConfig, config);

        // console.log(this.currentConfig);

        Oauth2Service.storage = new Oauth2Storage(this.currentConfig.storage);

        this.authHttp = new Oauth2AuthHttp(this.http, this);

        this.idToken = new Oauth2IdToken(this.window, this.currentConfig);
        this.accessToken = new Oauth2AccessToken(this.idToken, location, this.http, this);
        this.oauthProfile = new Oauth2Profile(this, this.accessToken);
        this.oidcConfig = new Oauth2OidcConfig(this.http);

        if (this.currentConfig.wellKnown) {
            this.oidcConfig.load(this.currentConfig);
        }

        this.initialized = true;

        Oauth2Service.Profile.subscribe(
            (item:Oauth2ProfileEvent) => {
                this.profile = item.profile;
            }
        );
    }

    public tryLogin() {
        this.accessToken.set();
    }

    public login(redirectTo?: string) {
        if (redirectTo) {
            this.currentConfig.redirectUri = redirectTo;
        }
        Oauth2Service.Login.emit({});
        let url = this.buildOauthUrl(this.currentConfig.authorizePath);
        this.location.replace(url);
    }

    public logout() {
        Oauth2Service.Logout.emit({});
        let destroyUrl: string = null;
        if (this.currentConfig.destroyTokenPath) {
            destroyUrl = this.currentConfig.site + this.currentConfig.destroyTokenPath;
        }
        this.accessToken.clearSession(destroyUrl);

        Oauth2Service.LoggedOut.emit({});

        if (this.currentConfig.logOutPath) {
            let url = this.buildOauthUrl(this.currentConfig.logOutPath);
            this.location.replace(url);
        }
    }

    public getAuthHttp() {
        return this.authHttp;
    }

    public getToken() {
        return this.accessToken;
    }

    public getProfile() {
        return this.profile;
    }

    private buildOauthUrl(path: string) {
        let oAuthScope = (this.currentConfig.scope) ? encodeURIComponent(this.currentConfig.scope) : '',
            state = (this.currentConfig.state) ? encodeURIComponent(this.currentConfig.state) : '',
            authPathHasQuery = (path.indexOf('?') === -1) ? false : true,
            appendChar = (authPathHasQuery) ? '&' : '?',    // if authorizePath has ? already append OAuth2 params
            nonceParam = (this.currentConfig.useNonce) ? '&nonce=' + this.generateNonce() : '',
            responseType = encodeURIComponent(this.currentConfig.responseType);

        if (state === '' && this.currentConfig.generateState ) {
            state = encodeURIComponent(this.generateState());
        }
        // console.log(nonceParam);

        return this.currentConfig.site +
            path +
            appendChar + 'response_type=' + responseType + '&' +
            'client_id=' + encodeURIComponent(this.currentConfig.clientId) + '&' +
            'redirect_uri=' + encodeURIComponent(this.currentConfig.redirectUri) + '&' +
            'scope=' + oAuthScope + '&' +
            'state=' + state + nonceParam;
    }

    private generateRandomString(length: number) {
        return Math.random().toString(35).substring(2, (length + 2));
    }

    private generateNonce() {
        this.currentConfig.nonce = this.generateRandomString(15);
        return this.currentConfig.nonce;
    }

    private generateState() {
        this.currentConfig.state = this.generateRandomString(15);
        return this.currentConfig.state;
    }
}
