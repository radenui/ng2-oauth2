# ng2-oauth2

This package provides a Oauth2 and OpenId Connect implicit flow module for Angular2.

**This is a work in progress !!**

It has been largely ispired from :

- [oauth-ng](https://github.com/angularjs-oauth/oauth-ng)
- [angular2-oauth2](https://github.com/manfredsteyer/angular2-oauth2)
- [ng2-translate](https://github.com/ocombe/ng2-translate) for packaging

## Usage example

Into main.ts:

```javascript
import { OAUTH2_PROVIDERS } from 'ng2-oauth2/ng2-oauth2';
...
bootstrap(
	...
	OAUTH2_PROVIDERS
);
```

Into your main application component:

```javascript
import { Oauth2Service } from 'ng2-oauth2/ng2-oauth2';

export class AppComponent {
	constructor(private oauth2service: Oauth2Service) {
		this.oauth2service.init({
            site: 'https://my.oauth.server.site.com',
            redirectUri: 'http://localhost:3000',
            clientId: 'xxxxxxxxxxxxxxxxxxxxxx',
            wellKnown: true,
            issuer: 'https://my.oauth.server.site.com',
            scope: 'openid profile',
            responseType: 'token id_token',
            useNonce: true,
            profileUri: 'https://my.oauth.server.site.com/oauth/me/',
            destroyTokenPath: '/oauth/destroy/'
        });
	}
}
```

Into your authentication component (I use it in my navbar): 

```javascript
import { Component, OnInit, OnDestroy } from '@angular/core';
import { Oauth2Service } from 'ng2-oauth2/ng2-oauth2';

...

@Component({
    selector: 'my-navbar',
    templateUrl: 'app/shared/navbar/navbar.html',
    directives: [ROUTER_DIRECTIVES, CORE_DIRECTIVES]
})
export class NavbarComponent implements OnInit, OnDestroy {
	public profile = {};
    public loggedin = false;

    // Injects the service into the component
    constructor(private oAuthService: Oauth2Service, private location: Location) {}

	ngOnInit() {
		// Suscribe to interesting events
		Oauth2Service.Authorized.subscribe(item => {
            console.log('Authorized event captured ', item.token);
            this.loggedin = true;
        });
        Oauth2Service.LoggedOut.subscribe(item => {
            console.log('Logged out event captured');
            this.loggedin = false;
            this.profile = {};
        });
        Oauth2Service.Profile.subscribe(item => {
            console.log('Profile event captured');
            this.profile = item.profile;
        });

        // At load, tries to login (If contains fragments with "access_token")
        this.oAuthService.tryLogin();
    }

    ngOnDestroy() {
        Oauth2Service.LoggedIn.unsubscribe();
        Oauth2Service.Profile.unsubscribe();
        Oauth2Service.Authorized.unsubscribe();
    }

    login() {
        this.oAuthService.login(this.location.href);
    }

    logout() {
        this.oAuthService.logout();
    }
}
```

## Initialization parameters

| Param | type | default | Usage |
|-------|------|---------|-------|
| site  | string | `undefined` | Oauth / OpenId Connect site |
| redirectUri | string | `undefined` | Uri for redirection after login |
| authorizePath | string | '/oauth/authorize' | authorize endpoint |
| tokenPath | string | '/oauth/token' | token endpoint |
| destroyTokenPath | string | `undefined` | token destruction endpoint (called with header 'Authorization: Bearer %access_token%') |
| responseType | string | 'token' | oauth response type ('token id_token' for OpenId Connect) |
| storage | Storage | `sessionStorage` | Storage for token, OIDC configuration. Can be `sessionStorage` or `localStorage` |
| profileUri | string | `undefined` | endpoint to get user Profile in JSON format |
| generateState | boolean | false | generate or not a state param for request |
| useNonce | boolean | false | generate or not a nonce param for request (mandatory for OpenId Connect) |
| issuer | string | `undefined` | Server where to get OpenIdConnect configuration |
| wellKnown | bool | false | use OpenId Connect .well-known/configuration endpoint to get informations about the server |
| logOutPath | string | `undefined` | If set, user will be redirected to this url to logout the Oauth server |
| state | string | `undefined` | set the state to this value in the oauth request |
| nonce | string | `undefined` | set the nonce to this value in the oauth request |


## Observable events

Events are triggered through static objects of service.

For instance: 

```javascript
// Emit event
Oauth2Service.Profile.emit({profile: profileObject});

// Subscribe to event
Oauth2Service.Profile.subscribe(
	(item) => console.log('Profile is: ', item.profile);

// Unsubscribe to event
Oauth2Service.Profile.unsubscribe();
```

| Event | Observed object | Description |
|-------|-----------------|-------------|
| Login | `{}` | Triggered when user calls the "login()" function |
| Logout | `{}` | Triggered when user calls the "logout()" function |
| LoggedIn | `{token: tokenObject}` | Triggered when user successfully logs in |
| Authorized | `{token: tokenObject}` | Triggered when user is authenticated (from session or hash parameters) |
| LoginError | `{}` | Triggered when user login fails |
| LoggedOut | `{}` | Triggered when user is not authenticated (no hash parameters, no session data) |
| TokenExpired | `{}` | Triggered when the user token is expired |
| TokenDestroyed | `{}` | Triggered when the user token is destroyed |
| TokenDestroyError | `{error: errorName, error_description: errorDescriptionString }` | Triggered when the user token destruction fails |
| Profile | `{profile: profileObject}` | Triggered when the user profile is set from the profileUri |
| ProfileError | `{error: errorName, error_description: errorDescriptionString }` | Triggered when the user profile fails |
| OIDCConfig | `{config: configObject}` | Triggered when the OIDC config is set from the server |
| OIDCKeys | `{config: configObject}` | Triggered when the OIDC keys are set from the server |
| OIDCConfigError | `{error: errorName, error_description: errorDescriptionString }` | Triggered when the OIDC config fails |
| OIDCKeysError | `{error: errorName, error_description: errorDescriptionString }` | Triggered when the OIDC keys fails |