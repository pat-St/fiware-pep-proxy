#!/usr/bin/env node
const cors = require('cors');
const config_service = require('./lib/config_service');

const fs = require('fs');
// const fsP = require("fs/promises");
const https = require('https');
const errorhandler = require('errorhandler');

const logger = require('morgan');
const debug = require('debug')('pep-proxy:app');
const express = require('express');


const path = require('path');
const got = require('got');

process.on('uncaughtException', function (err) {
  debug('Caught exception: ' + err);
});
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const { Writable } = require('stream');

class WriteStream extends Writable {
  constructor(filename) {
    super();
    this.filename = filename;
    this.fd = null;
    this.construct(this.doNothing)
  }

  doNothing(s = null) {
    if (s) { console.debug(s) }
  }
  construct(callback) {
    // fsP.open(this.filename, "w").then((of) => {
    // this.fd = of
    // }).finally(() => {
    callback();
    // })
  }

  write(chunk) {
    const cb = function (a = null, b = null, c = null) {
      if (a) { console.debug(a + b + c) }
    }
    console.debug(JSON.parse(Buffer.from(chunk).toString("utf-8")))
    try {
      let loggingProcess = Promise.resolve(true);
      if (process.env.PEP_LOGGING_REMOTE.toLowerCase() === "true") {
        loggingProcess = got.post(process.env.PEP_LOGGING_TARGET, {
          headers: {
            "Content-Type": "application/json"
          },
          body: Buffer.from(chunk).toString("utf-8")
        })
      }
      loggingProcess.then(() => {
        // this.fd.write(chunk)
        this.fd = fs.openSync(this.filename, "a");
        fs.appendFileSync(this.fd, chunk);
        fs.closeSync(this.fd);
      });
    } catch (error) {
      console.log("failed send data to usage control")
    } finally {
      cb();
    }
    // got.post(process.env.PEP_LOGGING_TARGET, {
    //   headers: {
    //     "Content-Type": "application/json"
    //   },
    //   body: Buffer.from(chunk).toString("utf-8")
    // }).then(() => this.fd.write(chunk))
    // .catch((err) =>console.log(err))
    // .finally(() => cb())
  }

  destroy(err, callback) {
    if (this.fd) {
      fs.close(this.fd, (er) => callback(er || err));
    } else {
      callback(err);
    }
  }
}

const lopperTarget = new WriteStream(path.join(__dirname, `access.log`));


/**
 * Start the express server to listen to all requests. Whitelisted public paths are
 * proxied directly, all other requests are restricted access and must either:
 *
 * - hold a bearer token from an authenticated user
 * - hold a bearer token and the user must be authorized to perform the action
 *
 * @param an auth token representing the PEP
 * @param the configuration to use within the app
 *
 * @return a running express server
 */
exports.start_server = function (token, config) {
  config_service.set_config(config, true);
  const Root = require('./controllers/root');
  const Payload = require('./lib/payload_analyse');
  const Authorize = require('./lib/authorization_functions');
  const app = express();
  let server;

  // Set logs in development
  if (config.debug) {
    app.use(logger('dev'));
  }

  app.use(logger(function (tokens, req, res) {
    const payload = {
      action: tokens.method(req, res),
      url: tokens.url(req, res),
      status: parseInt(tokens.status(req, res)),
      token: tokens.req(req, res, "X-Auth-Token"),
      agent: tokens['user-agent'](req),
      sourceAddr: tokens['remote-addr'](req),
      remoteUser: tokens.req(req, res, "X-User") || tokens['remote-user'](req),
      targetAddr: tokens.req(req, res, "fiware-service") || config.app.host + ":" + config.app.port,
      contentLength: tokens.res(req, res, 'content-length'),
      timestamp: tokens.date(req, res, "iso"),
      responseTime: tokens['response-time'](req, res),
    }
    return JSON.stringify(payload);
  }, { stream: lopperTarget }));

  app.use(function (req, res, next) {
    const bodyChunks = [];
    req.on('data', function (chunk) {
      bodyChunks.push(chunk);
    });

    req.on('end', function () {
      if (bodyChunks.length > 0) {
        req.body = Buffer.concat(bodyChunks);
      }
      next();
    });
  });

  app.disable('x-powered-by');
  app.use(errorhandler({ log: debug }));
  app.use(cors(config.cors));

  let port = config.pep_port || 80;
  if (config.https.enabled) {
    port = config.https.port || 443;
  }
  app.set('port', port);
  app.set('pepToken', token);
  app.set('trust proxy', '127.0.0.1');

  // The auth mode (authorize or authenticate only) and PDP to adjudicate
  // are set in the config.
  debug(
    'Starting PEP proxy on port ' +
    port +
    (config.authorization.enabled
      ? '. PDP authorization via ' + config.authorization.pdp
      : '. User authentication via IDM')
  );

  for (const p in config.public_paths) {
    debug('Public paths', config.public_paths[p]);
    app.all(config.public_paths[p], Root.open_access);
  }

  if (Authorize.checkPayload()) {
    // Oddity for Subscriptions
    app.post('/*/subscriptions', Payload.subscription, Root.restricted_access);
    app.patch('/*/subscriptions/*', Payload.subscription, Root.restricted_access);
    // Oddity for NGSI-v2
    app.all('/*/op/*', Payload.v2batch, Root.restricted_access);
    app.use(Payload.query);
    app.use(Payload.body);
    app.all('/*/entities/:id', Payload.params, Root.restricted_access);
    app.all('/*/entities/:id/attrs', Payload.params, Root.restricted_access);
    app.all('/*/entities/:id/attrs/:attr', Payload.params, Root.restricted_access);
  }

  app.all('/*', Root.restricted_access);

  if (config.https.enabled === true) {
    const options = {
      key: fs.readFileSync(config.https.key_file),
      cert: fs.readFileSync(config.https.cert_file)
    };

    server = https
      .createServer(options, function (req, res) {
        app.handle(req, res);
      })
      .listen(app.get('port'));
  } else {
    server = app.listen(app.get('port'));
  }
  return server;
};
