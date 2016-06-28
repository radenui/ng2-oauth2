import { Oauth2IdToken } from './oauth2.id-token';
import { Oauth2Service } from './oauth2.service';
import { Http, Headers, Response} from '@angular/http';
import { Observable }     from 'rxjs/Observable';


export class Oauth2AccessToken {
    private token: any = null;
    private expiresAtEvent: any;
    private expiresAt: number;
    private hashFragmentKeys = [
        // Oauth2 keys per http://tools.ietf.org/html/rfc6749#section-4.2.2
        'access_token', 'token_type', 'expires_in', 'scope', 'state',
        'error', 'error_description',
        // Additional OpenID Connect key per http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
        'id_token'
    ];

    constructor(
        private idToken: Oauth2IdToken,
        private location: Location,
        private http: Http,
        private oauth2service: Oauth2Service) {
    }

    public get() {
        return this.token;
    }

    public set() {
        if (this.location.hash.indexOf('access_token') !== -1) {
            this.setTokenFromString(this.location.hash.substring(1));
        }
        if (null === this.token) {
            this.setTokenFromSession();
        }
        if (null === this.token) {
            Oauth2Service.LoggedOut.emit({});
        }
        return this.token;
    }

    /*
        Returns ms before token expires
    */
    public getRemainingTimeForToken() {
        if (this.expiresAtEvent) {
            return this.expiresAt - new Date().getTime();
        } else {
            return -1;
        }
    }

    public clearSession(destroyTokenPath: string) {
        Oauth2Service.getStorage().remove(Oauth2Service.STORAGE_KEY_PROFILE);
        Oauth2Service.getStorage().remove(Oauth2Service.STORAGE_KEY_TOKEN);
        if (destroyTokenPath) {
            this.oauth2service.getAuthHttp().get(destroyTokenPath)
                .subscribe(
                    (res) => this.extractDestroyResponse(res),
                    (err) => this.handleDestroyError(err),
                    () => Oauth2Service.TokenDestroyed.emit({})
                );
        }
        this.token = null;
    }

    private extractDestroyResponse(res: Response) {
        let body = res.json();
        return body.data || { };
    }

    private handleDestroyError(error: any) {
        let errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
        Oauth2Service.TokenDestroyError.emit({error: error.name, error_description: errMsg});
        return Observable.throw(errMsg);
    }

    private setTokenFromString(hash: string) {
        let params: any = this.getTokenFromString(hash);
        if (params) {
            if (params.error || params.error_description) {
                Oauth2Service.LoginError.emit({error: params.error, error_description: params.error_description});
            } else {
                Oauth2Service.LoggedIn.emit({token: this.token});
                this.removeFragment();
                this.setToken(params);
                this.setExpiresAt();
                // We have to save it again to make sure expires_at is set
                //  and the expiry event is set up properly
                this.setToken(this.token);
                Oauth2Service.Authorized.emit({token: this.token});
            }
        }
    };

    private getTokenFromString(hash: string) {
        let params: any = {},
            regex = /([^&=]+)=([^&]*)/g,
            m: any;

        while ((m = regex.exec(hash)) !== null) {
          params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }

        // OpenID Connect
        if (params.id_token && !params.error) {
          this.idToken.validateTokensAndPopulateClaims(params);
          return params;
        }

        // Oauth2
        if (params.access_token || params.error) {
          return params;
        }
    };

    /**
    * Set the access token from the sessionStorage.
    */
    private setTokenFromSession() {
        let params = Oauth2Service.getStorage().getJson(Oauth2Service.STORAGE_KEY_TOKEN);

        if (params) {
            // controls token validity
            let now = new Date();
            if (params.expires_at && (new Date(params.expires_at).getTime() > now.getTime()) ) {
                this.setToken(params);
                Oauth2Service.Authorized.emit({token: this.token});
            } else {
                this.clearSession(null);
                Oauth2Service.TokenExpired.emit({});
            }
        }
    };

    /**
    * Save the access token into the session
    */
    private setTokenInSession() {
        Oauth2Service.getStorage().setJson(Oauth2Service.STORAGE_KEY_TOKEN, this.token);
    };

    /**
    * Set the access token expiration date (useful for refresh logics)
    */
    private setExpiresAt() {
        if (!this.token) {
            return;
        }
        if ( typeof(this.token.expires_in) !== 'undefined' && this.token.expires_in !== null) {
            let expires_at = new Date();
            expires_at.setSeconds(
                expires_at.getSeconds() +
                parseInt(this.token.expires_in, 10) - 60
            ); // 60 seconds less to secure browser and response latency
            this.token.expires_at = expires_at;
        } else {
            this.token.expires_at = null;
        }
    };

    /**
    * Set the access token.
    *
    * @param params
    * @returns {*|{}}
    */
    private setToken(params: any) {
        this.token = this.token || {};      // init the token
        Object.assign(this.token, params);      // set the access token params
        this.setTokenInSession();                // save the token into the session
        this.setExpiresAtEvent();                // event to fire when the token expires
        return this.token;
    };


    /**
    * Set the timeout at which the expired event is fired
    */
    private setExpiresAtEvent() {
        // Don't bother if there's no expires token
        if (typeof(this.token.expires_at) === 'undefined' || this.token.expires_at === null) {
            return;
        }
        this.cancelExpiresAtEvent();
        let time = (new Date(this.token.expires_at)).getTime() - (new Date()).getTime();
        if (time && time > 0 && time <= 2147483647) {
            this.expiresAt = new Date(this.token.expires_at).getTime();
            this.expiresAtEvent = setInterval(() => {
                    Oauth2Service.TokenExpired.emit({});
                }, time);
        }
    };

    private cancelExpiresAtEvent() {
        if (this.expiresAtEvent) {
            clearInterval(this.expiresAtEvent);
            this.expiresAtEvent = undefined;
        }
    };

    /**
    * Remove the oAuth2 pieces from the hash fragment
    */
    private removeFragment() {
        let curHash = this.location.hash;
        for (let hashKey in this.hashFragmentKeys) {
            if (hashKey && hashKey !== '') {
                let re = new RegExp('&' + hashKey + '(=[^&]*)?|^' + hashKey + '(=[^&]*)?&?');
                curHash = curHash.replace(re, '');
            }
        }
        this.location.hash = curHash;
    };
}
