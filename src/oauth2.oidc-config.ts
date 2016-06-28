import { Http } from '@angular/http';
import { Observable }     from 'rxjs/Observable';
import { Oauth2Service } from './oauth2.service';

export class Oauth2OidcConfig {
    private cache: any = null;

    constructor(private http: Http) {};

    public load(config: any) {
        this.cache = Oauth2Service.getStorage().getJson(Oauth2Service.STORAGE_KEY_OIDC_CONFIG);
        if (config.issuer && config.wellKnown && !this.cache) {
            this.loadConfig(config.issuer);
        }
    }

    private loadConfig(iss: string) {
        let configUri = this.joinPath(iss, '.well-known/openid-configuration');
        this.http.get(configUri)
            .subscribe(
                (data) => {
                    // Sets the cache
                    this.cache = data.json();
                    // Saves it
                    Oauth2Service.getStorage().setJson(Oauth2Service.STORAGE_KEY_OIDC_CONFIG, this.cache);
                },
                (err) => this.handleConfigError(err),
                () => {
                    Oauth2Service.OIDCConfig.emit({config: this.cache});
                    // LoadsJKS
                    this.loadJwks(this.cache);
                }
            );
    }

    private joinPath(x: string, y: string) {
      return x + (x.charAt(x.length - 1) === '/' ? '' : '/') + y;
    }

    private loadJwks(oidcConf: any) {
        if (oidcConf.jwks_uri) {
            this.http.get(oidcConf.jwks_uri)
                .subscribe(
                    (data) => {
                        oidcConf.jwks = data.json();
                        this.cache = oidcConf;
                        Oauth2Service.getStorage().setJson(Oauth2Service.STORAGE_KEY_OIDC_CONFIG, this.cache);
                    },
                    (err) => this.handleKeysError(err),
                    () => Oauth2Service.OIDCKeys.emit({config: this.cache})
                );
        }
    }

    private handleConfigError(error: any) {
        let errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
        Oauth2Service.OIDCConfigError.emit({error: error.name, error_description: errMsg});
        return Observable.throw(errMsg);
    }

    private handleKeysError(error: any) {
        let errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
        Oauth2Service.OIDCKeysError.emit({error: error.name, error_description: errMsg});
        return Observable.throw(errMsg);
    }


}
