import { Http, Headers, Response} from '@angular/http';
import { Observable }     from 'rxjs/Observable';
import { Oauth2AccessToken } from './oauth2.access-token';
import { Oauth2Service , Oauth2TokenEvent} from './oauth2.service';

export class Oauth2Profile {
    private profile = {};
    constructor(private oauthService: Oauth2Service , private accessToken: Oauth2AccessToken) {
        Oauth2Service.Authorized.subscribe(
            (item: Oauth2TokenEvent) => {
                let conf = oauthService.getCurrentConfig();
                this.loadProfile(conf);
            }
        );
    }

    public loadProfile(config: any) {
        let profile = Oauth2Service.getStorage().getJson(Oauth2Service.STORAGE_KEY_PROFILE);
        if (profile) {
            this.profile = profile;
            Oauth2Service.Profile.emit({profile: this.profile});
        } else if (config.profileUri && this.accessToken.get() && this.accessToken.get().access_token) {
            this.oauthService.getAuthHttp().get(config.profileUri)
                .subscribe(
                    (data) => this.handleProfile(data),
                    (err) => this.handleProfileError(err),
                    () => Oauth2Service.Profile.emit({profile: this.profile})
                );
        }
    }

    public getProfile() {
        return this.profile;
    }

    private handleProfile(res: Response) {
        this.profile = res.json();
        Oauth2Service.getStorage().setJson(Oauth2Service.STORAGE_KEY_PROFILE, this.profile);
        return res;
    }

    private handleProfileError(error: any) {
        let errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
        Oauth2Service.ProfileError.emit({error: error.name, error_description: errMsg});
        return Observable.throw(errMsg);
    }

}
