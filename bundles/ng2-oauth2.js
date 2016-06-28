System.registerDynamic("src/oauth2.access-token", ["./oauth2.service", "rxjs/Observable"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var oauth2_service_1 = $__require('./oauth2.service');
  var Observable_1 = $__require('rxjs/Observable');
  var Oauth2AccessToken = (function() {
    function Oauth2AccessToken(idToken, location, http, oauth2service) {
      this.idToken = idToken;
      this.location = location;
      this.http = http;
      this.oauth2service = oauth2service;
      this.token = null;
      this.hashFragmentKeys = ['access_token', 'token_type', 'expires_in', 'scope', 'state', 'error', 'error_description', 'id_token'];
    }
    Oauth2AccessToken.prototype.get = function() {
      return this.token;
    };
    Oauth2AccessToken.prototype.set = function() {
      if (this.location.hash.indexOf('access_token') !== -1) {
        this.setTokenFromString(this.location.hash.substring(1));
      }
      if (null === this.token) {
        this.setTokenFromSession();
      }
      if (null === this.token) {
        oauth2_service_1.Oauth2Service.LoggedOut.emit({});
      }
      return this.token;
    };
    Oauth2AccessToken.prototype.getRemainingTimeForToken = function() {
      if (this.expiresAtEvent) {
        return this.expiresAt - new Date().getTime();
      } else {
        return -1;
      }
    };
    Oauth2AccessToken.prototype.clearSession = function(destroyTokenPath) {
      var _this = this;
      oauth2_service_1.Oauth2Service.getStorage().remove(oauth2_service_1.Oauth2Service.STORAGE_KEY_PROFILE);
      oauth2_service_1.Oauth2Service.getStorage().remove(oauth2_service_1.Oauth2Service.STORAGE_KEY_TOKEN);
      if (destroyTokenPath) {
        this.oauth2service.getAuthHttp().get(destroyTokenPath).subscribe(function(res) {
          return _this.extractDestroyResponse(res);
        }, function(err) {
          return _this.handleDestroyError(err);
        }, function() {
          return oauth2_service_1.Oauth2Service.TokenDestroyed.emit({});
        });
      }
      this.token = null;
    };
    Oauth2AccessToken.prototype.extractDestroyResponse = function(res) {
      var body = res.json();
      return body.data || {};
    };
    Oauth2AccessToken.prototype.handleDestroyError = function(error) {
      var errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
      oauth2_service_1.Oauth2Service.TokenDestroyError.emit({
        error: error.name,
        error_description: errMsg
      });
      return Observable_1.Observable.throw(errMsg);
    };
    Oauth2AccessToken.prototype.setTokenFromString = function(hash) {
      var params = this.getTokenFromString(hash);
      if (params) {
        if (params.error || params.error_description) {
          oauth2_service_1.Oauth2Service.LoginError.emit({
            error: params.error,
            error_description: params.error_description
          });
        } else {
          oauth2_service_1.Oauth2Service.LoggedIn.emit({token: this.token});
          this.removeFragment();
          this.setToken(params);
          this.setExpiresAt();
          this.setToken(this.token);
          oauth2_service_1.Oauth2Service.Authorized.emit({token: this.token});
        }
      }
    };
    ;
    Oauth2AccessToken.prototype.getTokenFromString = function(hash) {
      var params = {},
          regex = /([^&=]+)=([^&]*)/g,
          m;
      while ((m = regex.exec(hash)) !== null) {
        params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
      }
      if (params.id_token && !params.error) {
        this.idToken.validateTokensAndPopulateClaims(params);
        return params;
      }
      if (params.access_token || params.error) {
        return params;
      }
    };
    ;
    Oauth2AccessToken.prototype.setTokenFromSession = function() {
      var params = oauth2_service_1.Oauth2Service.getStorage().getJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_TOKEN);
      if (params) {
        var now = new Date();
        if (params.expires_at && (new Date(params.expires_at).getTime() > now.getTime())) {
          this.setToken(params);
          oauth2_service_1.Oauth2Service.Authorized.emit({token: this.token});
        } else {
          this.clearSession(null);
          oauth2_service_1.Oauth2Service.TokenExpired.emit({});
        }
      }
    };
    ;
    Oauth2AccessToken.prototype.setTokenInSession = function() {
      oauth2_service_1.Oauth2Service.getStorage().setJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_TOKEN, this.token);
    };
    ;
    Oauth2AccessToken.prototype.setExpiresAt = function() {
      if (!this.token) {
        return;
      }
      if (typeof(this.token.expires_in) !== 'undefined' && this.token.expires_in !== null) {
        var expires_at = new Date();
        expires_at.setSeconds(expires_at.getSeconds() + parseInt(this.token.expires_in, 10) - 60);
        this.token.expires_at = expires_at;
      } else {
        this.token.expires_at = null;
      }
    };
    ;
    Oauth2AccessToken.prototype.setToken = function(params) {
      this.token = this.token || {};
      Object.assign(this.token, params);
      this.setTokenInSession();
      this.setExpiresAtEvent();
      return this.token;
    };
    ;
    Oauth2AccessToken.prototype.setExpiresAtEvent = function() {
      if (typeof(this.token.expires_at) === 'undefined' || this.token.expires_at === null) {
        return;
      }
      this.cancelExpiresAtEvent();
      var time = (new Date(this.token.expires_at)).getTime() - (new Date()).getTime();
      if (time && time > 0 && time <= 2147483647) {
        this.expiresAt = new Date(this.token.expires_at).getTime();
        this.expiresAtEvent = setInterval(function() {
          oauth2_service_1.Oauth2Service.TokenExpired.emit({});
        }, time);
      }
    };
    ;
    Oauth2AccessToken.prototype.cancelExpiresAtEvent = function() {
      if (this.expiresAtEvent) {
        clearInterval(this.expiresAtEvent);
        this.expiresAtEvent = undefined;
      }
    };
    ;
    Oauth2AccessToken.prototype.removeFragment = function() {
      var curHash = this.location.hash;
      for (var hashKey in this.hashFragmentKeys) {
        if (hashKey && hashKey !== '') {
          var re = new RegExp('&' + hashKey + '(=[^&]*)?|^' + hashKey + '(=[^&]*)?&?');
          curHash = curHash.replace(re, '');
        }
      }
      this.location.hash = curHash;
    };
    ;
    return Oauth2AccessToken;
  }());
  exports.Oauth2AccessToken = Oauth2AccessToken;
  return module.exports;
});

System.registerDynamic("src/oauth2.oidc-config", ["rxjs/Observable", "./oauth2.service"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var Observable_1 = $__require('rxjs/Observable');
  var oauth2_service_1 = $__require('./oauth2.service');
  var Oauth2OidcConfig = (function() {
    function Oauth2OidcConfig(http) {
      this.http = http;
      this.cache = null;
    }
    ;
    Oauth2OidcConfig.prototype.load = function(config) {
      this.cache = oauth2_service_1.Oauth2Service.getStorage().getJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_OIDC_CONFIG);
      if (config.issuer && config.wellKnown && !this.cache) {
        this.loadConfig(config.issuer);
      }
    };
    Oauth2OidcConfig.prototype.loadConfig = function(iss) {
      var _this = this;
      var configUri = this.joinPath(iss, '.well-known/openid-configuration');
      this.http.get(configUri).subscribe(function(data) {
        _this.cache = data.json();
        oauth2_service_1.Oauth2Service.getStorage().setJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_OIDC_CONFIG, _this.cache);
      }, function(err) {
        return _this.handleConfigError(err);
      }, function() {
        oauth2_service_1.Oauth2Service.OIDCConfig.emit({config: _this.cache});
        _this.loadJwks(_this.cache);
      });
    };
    Oauth2OidcConfig.prototype.joinPath = function(x, y) {
      return x + (x.charAt(x.length - 1) === '/' ? '' : '/') + y;
    };
    Oauth2OidcConfig.prototype.loadJwks = function(oidcConf) {
      var _this = this;
      if (oidcConf.jwks_uri) {
        this.http.get(oidcConf.jwks_uri).subscribe(function(data) {
          oidcConf.jwks = data.json();
          _this.cache = oidcConf;
          oauth2_service_1.Oauth2Service.getStorage().setJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_OIDC_CONFIG, _this.cache);
        }, function(err) {
          return _this.handleKeysError(err);
        }, function() {
          return oauth2_service_1.Oauth2Service.OIDCKeys.emit({config: _this.cache});
        });
      }
    };
    Oauth2OidcConfig.prototype.handleConfigError = function(error) {
      var errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
      oauth2_service_1.Oauth2Service.OIDCConfigError.emit({
        error: error.name,
        error_description: errMsg
      });
      return Observable_1.Observable.throw(errMsg);
    };
    Oauth2OidcConfig.prototype.handleKeysError = function(error) {
      var errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
      oauth2_service_1.Oauth2Service.OIDCKeysError.emit({
        error: error.name,
        error_description: errMsg
      });
      return Observable_1.Observable.throw(errMsg);
    };
    return Oauth2OidcConfig;
  }());
  exports.Oauth2OidcConfig = Oauth2OidcConfig;
  return module.exports;
});

System.registerDynamic("src/oauth2.id-token", ["./oauth2.service"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var oauth2_service_1 = $__require('./oauth2.service');
  var OidcException = (function() {
    function OidcException(message) {
      if (message) {
        this.message = message;
      }
    }
    return OidcException;
  }());
  exports.OidcException = OidcException;
  var Oauth2IdToken = (function() {
    function Oauth2IdToken(window, params) {
      this.window = window;
      if (params.issuer) {
        this.issuer = params.issuer;
      }
      if (params.clientId) {
        this.clientId = params.clientId;
      }
      if (params.subject) {
        this.subject = params.subject;
      }
      if (params.pubKey) {
        this.pubKey = params.pubKey;
      }
    }
    Oauth2IdToken.prototype.validateTokensAndPopulateClaims = function(params) {
      var valid = false;
      var message = '';
      try {
        valid = this.validateIdToken(params.id_token);
        if (valid && params.access_token) {
          valid = this.validateAccessToken(params.id_token, params.access_token);
        }
      } catch (error) {
        console.log(error.message);
        message = error.message;
      }
      if (valid) {
        params.id_token_claims = this.getIdTokenPayload(params.id_token);
      } else {
        params.id_token = null;
        params.access_token = null;
        params.error = 'Failed to validate token:' + message;
      }
    };
    Oauth2IdToken.prototype.validateIdToken = function(idToken) {
      return this.verifyIdTokenSig(idToken) && this.verifyIdTokenInfo(idToken);
    };
    ;
    Oauth2IdToken.prototype.validateAccessToken = function(idToken, accessToken) {
      var header = this.getJsonObject(this.getIdTokenParts(idToken)[0]);
      if (header.at_hash) {
        var shalevel = header.alg.substr(2);
        if (shalevel !== '256' && shalevel !== '384' && shalevel !== '512') {
          throw new OidcException('Unsupported hash algorithm, expecting sha256, sha384, or sha512');
        }
        var md = new KJUR.crypto.MessageDigest({
          alg: 'sha' + shalevel,
          prov: 'cryptojs'
        });
        var hexStr = md.digestString(accessToken);
        var expected = this.window.hextob64u(hexStr.substring(0, 32));
        return expected === header.at_hash;
      } else {
        return true;
      }
    };
    ;
    Oauth2IdToken.prototype.verifyIdTokenSig = function(idToken) {
      var idtParts = this.getIdTokenParts(idToken);
      var header = this.getJsonObject(idtParts[0]);
      if (!header.alg || header.alg.substr(0, 2) !== 'RS') {
        throw new OidcException('Unsupported JWS signature algorithm ' + header.alg);
      }
      var matchedPubKey = null;
      if (header.jwk) {
        matchedPubKey = header.jwk;
        if (matchedPubKey.kid && header.kid && matchedPubKey.kid !== header.kid) {
          throw new OidcException('Json Web Key ID not match');
        }
      } else {
        var oidcConfig = oauth2_service_1.Oauth2Service.getStorage().getJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_OIDC_CONFIG);
        if (typeof oidcConfig !== 'undefined' && oidcConfig && oidcConfig.jwks && oidcConfig.jwks.keys) {
          oidcConfig.jwks.keys.forEach(function(key, index) {
            if (key.kid === header.kid) {
              matchedPubKey = key;
            }
          });
        } else {
          var jwk = this.getJsonObject(this.pubKey);
          matchedPubKey = jwk ? jwk : this.pubKey;
        }
      }
      if (!matchedPubKey) {
        throw new OidcException('No public key found to verify signature');
      }
      var response = this.rsaVerifyJWS(idToken, matchedPubKey, header.alg);
      console.log(response);
      return response;
    };
    ;
    Oauth2IdToken.prototype.verifyIdTokenInfo = function(idtoken) {
      var valid = false;
      if (idtoken) {
        var idtParts = this.getIdTokenParts(idtoken);
        var payload = this.getJsonObject(idtParts[1]);
        if (payload) {
          var now = (new Date()).getTime() / 1000;
          if (payload.iat > now + 60) {
            throw new OidcException('ID Token issued time is later than current time');
          }
          if (payload.exp < now) {
            throw new OidcException('ID Token expired');
          }
          if (now < payload.ntb) {
            throw new OidcException('ID Token is invalid before ' + payload.ntb);
          }
          if (payload.iss && this.issuer && payload.iss !== this.issuer) {
            throw new OidcException('Invalid issuer ' + payload.iss + ' != ' + this.issuer);
          }
          if (payload.sub && this.subject && payload.sub !== this.subject) {
            throw new OidcException('Invalid subject ' + payload.sub + ' != ' + this.subject);
          }
          if (payload.aud) {
            if (payload.aud instanceof Array && !KJUR.jws.JWS.inArray(this.clientId, payload.aud)) {
              throw new OidcException('Client not in intended audience:' + payload.aud);
            }
            if (typeof payload.aud === 'string' && payload.aud !== this.clientId) {
              throw new OidcException('Invalid audience ' + payload.aud + ' != ' + this.clientId);
            }
          }
          valid = true;
        } else {
          throw new OidcException('Unable to parse JWS payload');
        }
      }
      return valid;
    };
    ;
    Oauth2IdToken.prototype.rsaVerifyJWS = function(jws, pubKey, alg) {
      var rsaKey = KEYUTIL.getKey(pubKey);
      return KJUR.jws.JWS.verify(jws, rsaKey, [alg]);
    };
    ;
    Oauth2IdToken.prototype.getIdTokenParts = function(id_token) {
      var jws = new KJUR.jws.JWS();
      jws.parseJWS(id_token);
      return [jws.parsedJWS.headS, jws.parsedJWS.payloadS, jws.parsedJWS.si];
    };
    ;
    Oauth2IdToken.prototype.getIdTokenPayload = function(id_token) {
      var parts = this.getIdTokenParts(id_token);
      if (parts) {
        return this.getJsonObject(parts[1]);
      }
    };
    ;
    Oauth2IdToken.prototype.getJsonObject = function(jsonS) {
      var jws = KJUR.jws.JWS;
      if (jws.isSafeJSONString(jsonS)) {
        return jws.readSafeJSONString(jsonS);
      }
      return null;
    };
    ;
    return Oauth2IdToken;
  }());
  exports.Oauth2IdToken = Oauth2IdToken;
  return module.exports;
});

System.registerDynamic("src/oauth2.storage", [], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var Oauth2Storage = (function() {
    function Oauth2Storage(storage) {
      this.storage = storage;
      this.cache = {};
      for (var i = 0; i < this.storage.length; i++) {
        this.cache[this.storage.key(i)] = this.storage.getItem(this.storage.key(i));
      }
    }
    Oauth2Storage.prototype.set = function(key, value) {
      this.cache[key] = value;
      this.saveCache(key);
      return this.cache[key];
    };
    Oauth2Storage.prototype.setJson = function(key, value) {
      this.cache[key] = JSON.stringify(value);
      this.saveCache(key);
      return this.cache[key];
    };
    Oauth2Storage.prototype.get = function(key) {
      if (this.cache[key]) {
        return this.cache[key];
      } else {
        return this.storage.getItem(key);
      }
    };
    Oauth2Storage.prototype.getJson = function(key) {
      return JSON.parse(this.get(key));
    };
    Oauth2Storage.prototype.remove = function(key) {
      this.storage.removeItem(key);
    };
    Oauth2Storage.prototype.saveCache = function(key) {
      this.storage.setItem(key, this.cache[key]);
    };
    return Oauth2Storage;
  }());
  exports.Oauth2Storage = Oauth2Storage;
  return module.exports;
});

System.registerDynamic("src/oauth2.profile", ["rxjs/Observable", "./oauth2.service"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var Observable_1 = $__require('rxjs/Observable');
  var oauth2_service_1 = $__require('./oauth2.service');
  var Oauth2Profile = (function() {
    function Oauth2Profile(oauthService, accessToken) {
      var _this = this;
      this.oauthService = oauthService;
      this.accessToken = accessToken;
      this.profile = {};
      oauth2_service_1.Oauth2Service.Authorized.subscribe(function(item) {
        var conf = oauthService.getCurrentConfig();
        _this.loadProfile(conf);
      });
    }
    Oauth2Profile.prototype.loadProfile = function(config) {
      var _this = this;
      var profile = oauth2_service_1.Oauth2Service.getStorage().getJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_PROFILE);
      if (profile) {
        this.profile = profile;
        oauth2_service_1.Oauth2Service.Profile.emit({profile: this.profile});
      } else if (config.profileUri && this.accessToken.get() && this.accessToken.get().access_token) {
        this.oauthService.getAuthHttp().get(config.profileUri).subscribe(function(data) {
          return _this.handleProfile(data);
        }, function(err) {
          return _this.handleProfileError(err);
        }, function() {
          return oauth2_service_1.Oauth2Service.Profile.emit({profile: _this.profile});
        });
      }
    };
    Oauth2Profile.prototype.getProfile = function() {
      return this.profile;
    };
    Oauth2Profile.prototype.handleProfile = function(res) {
      this.profile = res.json();
      oauth2_service_1.Oauth2Service.getStorage().setJson(oauth2_service_1.Oauth2Service.STORAGE_KEY_PROFILE, this.profile);
      return res;
    };
    Oauth2Profile.prototype.handleProfileError = function(error) {
      var errMsg = (error.message) ? error.message : error.status ? error.status + '-' + error.statusText : 'Server error';
      oauth2_service_1.Oauth2Service.ProfileError.emit({
        error: error.name,
        error_description: errMsg
      });
      return Observable_1.Observable.throw(errMsg);
    };
    return Oauth2Profile;
  }());
  exports.Oauth2Profile = Oauth2Profile;
  return module.exports;
});

System.registerDynamic("src/oauth2.service", ["@angular/core", "@angular/http", "./oauth2.access-token", "./oauth2.oidc-config", "./oauth2.id-token", "./oauth2.storage", "./oauth2.profile", "./oauth2.auth-http"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var __decorate = (this && this.__decorate) || function(decorators, target, key, desc) {
    var c = arguments.length,
        r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc,
        d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function")
      r = Reflect.decorate(decorators, target, key, desc);
    else
      for (var i = decorators.length - 1; i >= 0; i--)
        if (d = decorators[i])
          r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
  };
  var __metadata = (this && this.__metadata) || function(k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function")
      return Reflect.metadata(k, v);
  };
  var core_1 = $__require('@angular/core');
  var http_1 = $__require('@angular/http');
  var oauth2_access_token_1 = $__require('./oauth2.access-token');
  var oauth2_oidc_config_1 = $__require('./oauth2.oidc-config');
  var oauth2_id_token_1 = $__require('./oauth2.id-token');
  var oauth2_storage_1 = $__require('./oauth2.storage');
  var oauth2_profile_1 = $__require('./oauth2.profile');
  var oauth2_auth_http_1 = $__require('./oauth2.auth-http');
  ;
  ;
  ;
  ;
  ;
  var Oauth2Service = (function() {
    function Oauth2Service(window, location, http) {
      this.window = window;
      this.location = location;
      this.http = http;
      this.defaultConfig = {
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
      this.currentConfig = this.defaultConfig;
      this.initialized = false;
    }
    Oauth2Service.getStorage = function() {
      return Oauth2Service.storage;
    };
    Oauth2Service.prototype.getCurrentConfig = function() {
      return this.currentConfig;
    };
    Oauth2Service.prototype.init = function(config) {
      var _this = this;
      var requiredParams = ['site', 'clientId', 'redirectUri'];
      for (var p in requiredParams) {
        if (typeof config[p] === undefined) {
          throw new Error('Missing config parameter ' + p);
        }
      }
      this.currentConfig = Object.assign(this.currentConfig, config);
      Oauth2Service.storage = new oauth2_storage_1.Oauth2Storage(this.currentConfig.storage);
      this.authHttp = new oauth2_auth_http_1.Oauth2AuthHttp(this.http, this);
      this.idToken = new oauth2_id_token_1.Oauth2IdToken(this.window, this.currentConfig);
      this.accessToken = new oauth2_access_token_1.Oauth2AccessToken(this.idToken, location, this.http, this);
      this.oauthProfile = new oauth2_profile_1.Oauth2Profile(this, this.accessToken);
      this.oidcConfig = new oauth2_oidc_config_1.Oauth2OidcConfig(this.http);
      if (this.currentConfig.wellKnown) {
        this.oidcConfig.load(this.currentConfig);
      }
      this.initialized = true;
      Oauth2Service.Profile.subscribe(function(item) {
        _this.profile = item.profile;
      });
    };
    Oauth2Service.prototype.tryLogin = function() {
      this.accessToken.set();
    };
    Oauth2Service.prototype.login = function(redirectTo) {
      if (redirectTo) {
        this.currentConfig.redirectUri = redirectTo;
      }
      Oauth2Service.Login.emit({});
      var url = this.buildOauthUrl(this.currentConfig.authorizePath);
      this.location.replace(url);
    };
    Oauth2Service.prototype.logout = function() {
      Oauth2Service.Logout.emit({});
      var destroyUrl = null;
      if (this.currentConfig.destroyTokenPath) {
        destroyUrl = this.currentConfig.site + this.currentConfig.destroyTokenPath;
      }
      this.accessToken.clearSession(destroyUrl);
      Oauth2Service.LoggedOut.emit({});
      if (this.currentConfig.logOutPath) {
        var url = this.buildOauthUrl(this.currentConfig.logOutPath);
        this.location.replace(url);
      }
    };
    Oauth2Service.prototype.getAuthHttp = function() {
      return this.authHttp;
    };
    Oauth2Service.prototype.getToken = function() {
      return this.accessToken;
    };
    Oauth2Service.prototype.getProfile = function() {
      return this.profile;
    };
    Oauth2Service.prototype.buildOauthUrl = function(path) {
      var oAuthScope = (this.currentConfig.scope) ? encodeURIComponent(this.currentConfig.scope) : '',
          state = (this.currentConfig.state) ? encodeURIComponent(this.currentConfig.state) : '',
          authPathHasQuery = (path.indexOf('?') === -1) ? false : true,
          appendChar = (authPathHasQuery) ? '&' : '?',
          nonceParam = (this.currentConfig.useNonce) ? '&nonce=' + this.generateNonce() : '',
          responseType = encodeURIComponent(this.currentConfig.responseType);
      if (state === '' && this.currentConfig.generateState) {
        state = encodeURIComponent(this.generateState());
      }
      return this.currentConfig.site + path + appendChar + 'response_type=' + responseType + '&' + 'client_id=' + encodeURIComponent(this.currentConfig.clientId) + '&' + 'redirect_uri=' + encodeURIComponent(this.currentConfig.redirectUri) + '&' + 'scope=' + oAuthScope + '&' + 'state=' + state + nonceParam;
    };
    Oauth2Service.prototype.generateRandomString = function(length) {
      return Math.random().toString(35).substring(2, (length + 2));
    };
    Oauth2Service.prototype.generateNonce = function() {
      this.currentConfig.nonce = this.generateRandomString(15);
      return this.currentConfig.nonce;
    };
    Oauth2Service.prototype.generateState = function() {
      this.currentConfig.state = this.generateRandomString(15);
      return this.currentConfig.state;
    };
    Oauth2Service.STORAGE_KEY_TOKEN = 'oauth2_token';
    Oauth2Service.STORAGE_KEY_OIDC_CONFIG = 'oauth2_oidc_config';
    Oauth2Service.STORAGE_KEY_PROFILE = 'oauth2_profile';
    Oauth2Service.Login = new core_1.EventEmitter();
    Oauth2Service.Logout = new core_1.EventEmitter();
    Oauth2Service.LoggedIn = new core_1.EventEmitter();
    Oauth2Service.Authorized = new core_1.EventEmitter();
    Oauth2Service.LoginError = new core_1.EventEmitter();
    Oauth2Service.LoggedOut = new core_1.EventEmitter();
    Oauth2Service.TokenExpired = new core_1.EventEmitter();
    Oauth2Service.TokenDestroyed = new core_1.EventEmitter();
    Oauth2Service.TokenDestroyError = new core_1.EventEmitter();
    Oauth2Service.Profile = new core_1.EventEmitter();
    Oauth2Service.ProfileError = new core_1.EventEmitter();
    Oauth2Service.OIDCConfig = new core_1.EventEmitter();
    Oauth2Service.OIDCKeys = new core_1.EventEmitter();
    Oauth2Service.OIDCConfigError = new core_1.EventEmitter();
    Oauth2Service.OIDCKeysError = new core_1.EventEmitter();
    Oauth2Service = __decorate([core_1.Injectable(), __metadata('design:paramtypes', [Window, Location, http_1.Http])], Oauth2Service);
    return Oauth2Service;
  }());
  exports.Oauth2Service = Oauth2Service;
  return module.exports;
});

System.registerDynamic("src/oauth2.auth-http", ["./oauth2.service", "@angular/http"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  var oauth2_service_1 = $__require('./oauth2.service');
  var http_1 = $__require('@angular/http');
  var AuthHttpException = (function() {
    function AuthHttpException(message) {
      if (message) {
        this.message = message;
      }
    }
    return AuthHttpException;
  }());
  exports.AuthHttpException = AuthHttpException;
  var Oauth2AuthHttp = (function() {
    function Oauth2AuthHttp(http, oauth2Service) {
      var _this = this;
      this.http = http;
      this.oauth2Service = oauth2Service;
      this.params = {
        headerKey: 'Authorization',
        headerValuePrefix: 'Bearer ',
        headerValueSuffix: ''
      };
      this.token = null;
      oauth2_service_1.Oauth2Service.Authorized.subscribe(function(data) {
        if (data.token) {
          _this.token = data.token.access_token;
        }
      });
      oauth2_service_1.Oauth2Service.LoggedOut.subscribe(function(data) {
        _this.token = null;
      });
    }
    Oauth2AuthHttp.prototype.setOptions = function(params) {
      this.params = params;
    };
    Oauth2AuthHttp.prototype.request = function(url, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.request(url, options);
    };
    Oauth2AuthHttp.prototype.get = function(url, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.get(url, options);
    };
    Oauth2AuthHttp.prototype.post = function(url, body, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.post(url, body, options);
    };
    Oauth2AuthHttp.prototype.put = function(url, body, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.put(url, body, options);
    };
    Oauth2AuthHttp.prototype.delete = function(url, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.delete(url, options);
    };
    Oauth2AuthHttp.prototype.patch = function(url, body, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.patch(url, body, options);
    };
    Oauth2AuthHttp.prototype.head = function(url, options) {
      if (this.token) {
        options = this.setHeaders(options);
      } else {
        throw new AuthHttpException('User not logged in');
      }
      return this.http.head(url, options);
    };
    Oauth2AuthHttp.prototype.setHeaders = function(options) {
      if (!options) {
        options = {headers: new http_1.Headers()};
      } else if (!options.headers) {
        options.headers = new http_1.Headers();
      }
      options.headers.append(this.params.headerKey, this.params.headerValuePrefix + this.token + this.params.headerValueSuffix);
      return options;
    };
    return Oauth2AuthHttp;
  }());
  exports.Oauth2AuthHttp = Oauth2AuthHttp;
  return module.exports;
});

System.registerDynamic("ng2-oauth2", ["./src/oauth2.service", "./src/oauth2.access-token", "./src/oauth2.id-token", "./src/oauth2.oidc-config", "./src/oauth2.auth-http"], true, function($__require, exports, module) {
  "use strict";
  ;
  var define,
      global = this,
      GLOBAL = this;
  function __export(m) {
    for (var p in m)
      if (!exports.hasOwnProperty(p))
        exports[p] = m[p];
  }
  var oauth2_service_1 = $__require('./src/oauth2.service');
  __export($__require('./src/oauth2.service'));
  __export($__require('./src/oauth2.access-token'));
  __export($__require('./src/oauth2.id-token'));
  __export($__require('./src/oauth2.oidc-config'));
  __export($__require('./src/oauth2.auth-http'));
  exports.OAUTH2_PROVIDERS = [oauth2_service_1.Oauth2Service];
  return module.exports;
});
