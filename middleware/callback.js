'use strict';
/**
 * The Callback authorization middleware is exposed as:
 * "uauth.callback"
 *
 * and will place the user object in the intent's "user" data field
 * intentObj.data('user')
 *
 * IF the request is an AJAX request, it will return a AUTH.ERROR error.
 * */
module.exports = (thorin, opt, uauthObj) => {

  const dispatcher = thorin.dispatcher,
    errorData = {
      url: uauthObj.getRedirect()
    },
    logger = thorin.logger(opt.logger);

  dispatcher
    .addAuthorization('uauth.callback')
    .input({
      token: dispatcher.validate('STRING').default(null)
    })
    .use((intentObj, next) => {
      let input = intentObj.input(),
        user,
        calls = [];

      if (!input.token) {
        return next(thorin.error('AUTH.ERROR', 'Authentication token is missing from URL', 401, errorData));
      }

      calls.push((stop) => {
        return uauthObj.dispatch('auth.token', {
          token: input.token
        }).then((res) => {
          user = res.result;
          if (typeof user !== 'object' || !user || !user.email) {
            return stop(thorin.error('AUTH.ERROR', 'User information could not be retrieved', 401, errorData));
          }
          intentObj.data('user', user);
        });
      });

      thorin.series(calls, (e) => {
        if (e) {
          if (e.statusCode >= 500) {
            logger.warn(`Could not perform uauth callback on token`);
            logger.debug(e);
          }
          if (e.ns !== 'AUTH') {
            e = thorin.error('AUTH.ERROR', 'An error occurred while authenticating you', 401, errorData);
          }
          return next(e);
        }
        next();
      });
    });
};