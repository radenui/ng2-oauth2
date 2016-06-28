import { Oauth2Service , Oauth2TokenEvent, Oauth2EmptyEvent} from './oauth2.service';
import { Http, Request, RequestOptionsArgs, Headers, Response} from '@angular/http';
import { Observable } from 'rxjs/Rx';


export class AuthHttpException implements Error {
    public name: 'AuthHttpException';
    public message: string;
    constructor(message?: string) {
        if (message) {
            this.message = message;
        }
    }
}

export class Oauth2AuthHttp {
    private params = {
        headerKey: 'Authorization',
        headerValuePrefix: 'Bearer ',
        headerValueSuffix: ''
    };

    private token: string = null;

    constructor(private http: Http, private oauth2Service: Oauth2Service) {
        Oauth2Service.Authorized.subscribe(
            (data: Oauth2TokenEvent) => {
                if (data.token) {
                    this.token = data.token.access_token;
                }
            }
        );
        Oauth2Service.LoggedOut.subscribe(
            (data: Oauth2EmptyEvent) => { this.token = null ; }
        );
    }

    public setOptions(params: any) {
        this.params = params;
    }

    /**
     * Performs any type of http request. First argument is required, and can either be a url or
     * a {@link Request} instance. If the first argument is a url, an optional {@link RequestOptions}
     * object can be provided as the 2nd argument. The options object will be merged with the values
     * of {@link BaseRequestOptions} before performing the request.
     */
    public request(url: string | Request, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
           options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.request(url, options);
    }
    /**
     * Performs a request with `get` http method.
     */
    public get(url: string, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.get(url, options);
    }
    /**
     * Performs a request with `post` http method.
     */
    public post(url: string, body: any, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.post(url, body, options);
    }
    /**
     * Performs a request with `put` http method.
     */
    public put(url: string, body: any, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.put(url, body, options);
    }
    /**
     * Performs a request with `delete` http method.
     */
    public delete(url: string, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.delete(url, options);
    }
    /**
     * Performs a request with `patch` http method.
     */
    public patch(url: string, body: any, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.patch(url, body, options);
    }
    /**
     * Performs a request with `head` http method.
     */
    public head(url: string, options?: RequestOptionsArgs): Observable<Response> {
        if (this.token) {
            options = this.setHeaders(options);
        } else {
            throw new AuthHttpException('User not logged in');
        }
        return this.http.head(url, options);
    }


    private setHeaders(options: any) {
        if (!options) {
            options = { headers: new Headers()};
        } else if (! options.headers ) {
            options.headers = new Headers();
        }
        options.headers.append(
            this.params.headerKey,
            this.params.headerValuePrefix + this.token + this.params.headerValueSuffix
        );
        return options;
    }
}
