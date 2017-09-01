'use strict';
const qs = require('qs'),
  callbackAuth = require('./middleware/callback');
/**
 * UNLOQ.io authorization middleware for thorin. This is the V2 authentication mechanism with UAuth2
 */
module.exports = function (thorin, opt, pluginName) {
  opt = thorin.util.extend({
    logger: pluginName || 'uauth',
    url: 'https://auth.unloq.io',
    switch: true,         // Enable organisation switch
    reauth: false,        // Enable reauth
    client_id: null,      // The UAUth client ID
    client_secret: null   // The UAuth client secret
  }, opt);
  const logger = thorin.logger(opt.logger);
  if (!opt.client_id) {
    logger.fatal('Missing Client ID');
  }
  if (!opt.client_secret) {
    logger.fatal(`Missing Client Secret`);
  }

  const apiObj = thorin.fetcher('uauthApi', opt.url + '/api');


  let uauthObj = {};

  /**
   * Generates an authorization token
   * */
  uauthObj.getAuthorizationToken = () => {
    let now = Date.now().toString(),
      hmac = thorin.util.hmac(now, opt.client_secret);
    let token = opt.client_id + '-' + now + '-' + hmac;
    return token;
  };

  /**
   * Calls the UAUth API endpoint with the given type/payload
   * */
  uauthObj.dispatch = (type, payload) => {
    if (!opt.client_id || !opt.client_secret) {
      logger.warn(`Failed to perform call to ${type}, no credentials given.`);
      return Promise.reject(thorin.error('AUTH.API', 'Could not initiate authentication request'));
    }
    return apiObj.dispatch(type, payload, {
      headers: {
        Authorization: uauthObj.getAuthorizationToken()
      }
    });
  };

  function getUrl(path, query) {
    let data = {
      client_id: opt.client_id
    };
    Object.keys(query).forEach((name) => {
      if (name === 'client_id' || name === 'token') return;
      data[name] = query[name];
    });
    let fullUrl = opt.url + path;
    try {
      let qsUrl = qs.stringify(data);
      fullUrl += '?' + qsUrl;
    } catch (e) {
      fullUrl += '?client_id=' + opt.client_id;
    }
    return fullUrl;
  }

  /**
   * Returns the redirect URL for authentication
   * */
  uauthObj.getRedirect = (query) => {
    if (typeof query !== 'object' || !query) query = {};
    if (opt.reauth && typeof query.reauth === 'undefined') {
      query.reauth = 'true';
    }
    if (opt.switch && typeof query.switch === 'undefined') {
      query.switch = 'organization';
    }
    return getUrl('/login', query);
  };

  /**
   * Returns the logout URL, so that the user can terminate his session.
   * */
  uauthObj.getLogout = (query) => {
    if (typeof query !== 'object' || !query) query = {};
    return getUrl('/logout', query);
  };

  /**
   * Announces the auth server that the user has logged out of his account and that we should
   * re-authenticate the user.
   * NOTE: this will NEVER reject.
   * */
  uauthObj.logout = (unloq_id) => {
    return uauthObj.dispatch('auth.logout', {
      unloq_id
    }).catch((e) => {
      logger.warn(`Could not terminate all sessions of user ${unloq_id}`);
      logger.debug(e);
    });
  };


  callbackAuth(thorin, opt, uauthObj);


  return uauthObj;
};
module.exports.publicName = 'uauth';