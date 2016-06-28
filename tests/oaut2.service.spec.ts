import {it, describe, expect } from "@angular/core/testing";
import {provide, Injector, ReflectiveInjector} from "@angular/core";
import {ResponseOptions, Response, HTTP_PROVIDERS, XHRBackend} from "@angular/http";
import {MockBackend, MockConnection} from "@angular/http/testing";
import { 
	Oauth2ProfileEvent,
	Oauth2TokenEvent,
	OAUTH2_PROVIDERS,
	Oauth2AccessToken,
	Oauth2ConfigEvent,
	Oauth2EmptyEvent,
	Oauth2ErrorEvent,
	Oauth2IdToken,
	Oauth2OidcConfig,
	Oauth2Service,
	OidcException,
	AuthHttpException, 
	Oauth2AuthHttp
}  from './../ng2-oauth2';
import {Observable} from "rxjs/Observable";

export function main() {
	describe('Oauth2Service', () => {
		it('Fake test', () => {
            expect(true).toEqual(true);
        });
	});
}