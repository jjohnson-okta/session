/*!
 * express-session
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * MIT Licensed
 */

/**
 * Module dependencies.
 */

var debug = require('debug')('express-session');
var deprecate = require('depd')('express-session');
var uid = require('uid-safe').sync
  , onHeaders = require('on-headers')
  , crc32 = require('buffer-crc32')
  , parse = require('url').parse;

var Session = require('./session/session')
  , MemoryStore = require('./session/memory')
  , Cookie = require('./session/cookie')
  , Store = require('./session/store')

// environment

var env = process.env.NODE_ENV;

/**
 * Expose the middleware.
 */

exports = module.exports = session;

/**
 * Expose constructors.
 */

exports.Store = Store;
exports.Cookie = Cookie;
exports.Session = Session;
exports.MemoryStore = MemoryStore;

/**
 * Warning message for `MemoryStore` usage in production.
 */

var warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.';

/**
 * Setup session store with the given `options`.
 *
 * See README.md for documentation of options and formatting.
 *
 * Session data is _not_ saved in the cookie itself, however cookies are used,
 * so you must use the cookie-parser middleware _before_ `session()`.
 * [https://github.com/expressjs/cookie-parser]
 *
 * @param {Object} options
 * @return {Function} middleware
 * @api public
 */

function session(options){
  var options = options || {}
  //  name - previously "options.key"
    , name = options.name || options.key || 'connect.sid'
    , store = options.store || new MemoryStore
    , cookie = options.cookie || {}
    , trustProxy = options.proxy
    , storeReady = true
    , rollingSessions = options.rolling || false;
  var resaveSession = options.resave;
  var saveUninitializedSession = options.saveUninitialized;

  var generateId = options.genid || generateSessionId;

  if (typeof generateId !== 'function') {
    throw new TypeError('genid option must be a function');
  }

  if (resaveSession === undefined) {
    deprecate('undefined resave option; provide resave option');
    resaveSession = true;
  }

  if (saveUninitializedSession === undefined) {
    deprecate('undefined saveUninitialized option; provide saveUninitialized option');
    saveUninitializedSession = true;
  }

  if (options.unset && options.unset !== 'destroy' && options.unset !== 'keep') {
    throw new TypeError('unset option must be "destroy" or "keep"');
  }

  // TODO: switch to "destroy" on next major
  var unsetDestroy = options.unset === 'destroy';

  // notify user that this store is not
  // meant for a production environment
  if ('production' == env && store instanceof MemoryStore) {
    console.warn(warning);
  }

  // generates the new session
  store.generate = function(req){
    req.sessionID = generateId(req);
    req.session = new Session(req);
    req.session.cookie = new Cookie(cookie);
  };

  store.on('disconnect', function(){ storeReady = false; });
  store.on('connect', function(){ storeReady = true; });

  return function session(req, res, next) {
    // self-awareness
    if (req.session) return next();

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    if (!storeReady) return debug('store is disconnected'), next();

    // pathname mismatch
    var originalPath = parse(req.originalUrl || req.url).pathname;
    if (0 != originalPath.indexOf(cookie.path || '/')) return next();

    var originalHash
      , originalId;

    // expose store
    req.sessionStore = store;

    // get the session ID from the cookie
    var cookieId = req.sessionID = getcookie(req, name);

    // set-cookie
    onHeaders(res, function(){
      if (!req.session) {
        debug('no session');
        return;
      }

      var cookie = req.session.cookie;

      // only send secure cookies via https
      if (cookie.secure && !issecure(req, trustProxy)) {
        debug('not secured');
        return;
      }

      if (!shouldSetCookie(req)) {
        return;
      }

      setcookie(res, name, req.sessionID, null, cookie.data);
    });

    // proxy end() to commit the session
    var end = res.end;
    var ended = false;
    res.end = function(chunk, encoding){
      if (ended) {
        return false;
      }

      var ret;
      var sync = true;

      if (chunk === undefined) {
        chunk = '';
      }

      ended = true;

      if (shouldDestroy(req)) {
        // destroy session
        debug('destroying');
        store.destroy(req.sessionID, function(err){
          if (err) console.error(err.stack);
          debug('destroyed');

          if (sync) {
            ret = end.call(res, chunk, encoding);
            sync = false;
            return;
          }

          end.call(res);
        });

        if (sync) {
          ret = res.write(chunk, encoding);
          sync = false;
        }

        return ret;
      }

      // no session to save
      if (!req.session) {
        debug('no session');
        return end.call(res, chunk, encoding);
      }

      req.session.resetMaxAge();

      if (shouldSave(req)) {
        debug('saving');
        req.session.save(function(err){
          if (err) console.error(err.stack);
          debug('saved');

          if (sync) {
            ret = end.call(res, chunk, encoding);
            sync = false;
            return;
          }

          end.call(res);
        });

        if (sync) {
          ret = res.write(chunk, encoding);
          sync = false;
        }

        return ret;
      }

      return end.call(res, chunk, encoding);
    };

    // generate the session
    function generate() {
      store.generate(req);
      originalId = req.sessionID;
      originalHash = hash(req.session);
    }

    // check if session has been modified
    function isModified(sess) {
      return originalHash != hash(sess) || originalId != sess.id;
    }

    // determine if session should be destroyed
    function shouldDestroy(req) {
      return req.sessionID && unsetDestroy && req.session == null;
    }

    // determine if session should be saved to store
    function shouldSave(req) {
      return cookieId != req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : resaveSession || isModified(req.session);
    }

    // determine if cookie should be set on response
    function shouldSetCookie(req) {
      // in case of rolling session, always reset the cookie
      if (rollingSessions) {
        return true;
      }

      return cookieId != req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : req.session.cookie.expires != null && isModified(req.session);
    }

    // generate a session if the browser doesn't send a sessionID
    if (!req.sessionID) {
      debug('no SID sent, generating session');
      generate();
      next();
      return;
    }

    // generate the session object
    debug('fetching %s', req.sessionID);
    store.get(req.sessionID, function(err, sess){
      // error handling
      if (err) {
        debug('error %j', err);
        if ('ENOENT' == err.code) {
          generate();
          next();
        } else {
          next(err);
        }
      // no session
      } else if (!sess) {
        debug('no session found');
        generate();
        next();
      // populate req.session
      } else {
        debug('session found');
        store.createSession(req, sess);
        originalId = req.sessionID;
        originalHash = hash(sess);
        next();
      }
    });
  };
};

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @api private
 */

function generateSessionId(sess) {
  return uid(24);
}

/**
 * Get the session ID cookie from request.
 *
 * @return {string}
 * @api private
 */

function getcookie(req, name) {
  return req.cookies.get(name);
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * @param {Object} sess
 * @return {String}
 * @api private
 */

function hash(sess) {
  return crc32.signed(JSON.stringify(sess, function(key, val){
    if ('cookie' != key) return val;
  }));
}

/**
 * Determine if request is secure.
 *
 * @param {Object} req
 * @param {Boolean} [trustProxy]
 * @return {Boolean}
 * @api private
 */

function issecure(req, trustProxy) {
  // socket is https server
  if (req.connection && req.connection.encrypted) {
    return true;
  }

  // do not trust proxy
  if (trustProxy === false) {
    return false;
  }

  // no explicit trust; try req.secure from express
  if (trustProxy !== true) {
    var secure = req.secure;
    return typeof secure === 'boolean'
      ? secure
      : false;
  }

  // read the proto from x-forwarded-proto header
  var header = req.headers['x-forwarded-proto'] || '';
  var index = header.indexOf(',');
  var proto = index !== -1
    ? header.substr(0, index).toLowerCase().trim()
    : header.toLowerCase().trim()

  return proto === 'https';
}

function setcookie(res, name, val, options) {
  res.cookies.set(name, val, options);
}
