/*
 * Copyright 2021 -  Universidad Politécnica de Madrid.
 *
 * This file is part of Keyrock
 *
 */

const got = require('got');
const should = require('should');
const nock = require('nock');
const cache = require('../../lib/cache');
const jwt = require('jsonwebtoken');
const StatusCodes = require('http-status-codes').StatusCodes;

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

const token = jwt.sign(
  {
    app_id: 'application_id',
    trusted_apps: [],
    id: 'username',
    displayName: 'Some User'
  },
  'shhhhh'
);

const invalid_token = jwt.sign(
  {
    app_id: 'application_id',
    trusted_apps: [],
    id: 'username',
    displayName: 'Some User'
  },
  'wrong_secret'
);

const expired_token = jwt.sign(
  {
    app_id: 'application_id',
    trusted_apps: [],
    id: 'username',
    displayName: 'Some User'
  },
  'shhhhh',
  { expiresIn: '1ms' }
);

const request_with_jwt = {
  prefixUrl: 'http:/localhost:1026',
  throwHttpErrors: false,
  headers: { 'x-auth-token': token }
};

const request_with_invalid_jwt = {
  prefixUrl: 'http:/localhost:1026',
  throwHttpErrors: false,
  headers: { 'x-auth-token': invalid_token },
  retry: 0
};

const request_no_jwt = {
  prefixUrl: 'http:/localhost:1026',
  throwHttpErrors: false
};

const request_with_expired_jwt = {
  prefixUrl: 'http:/localhost:1026',
  throwHttpErrors: false,
  headers: { 'x-auth-token': expired_token }
};

const config = {
  magic_key: '999999999',
  pep_port: 1026,
  pep: {
    app_id: 'application_id',
    trusted_apps: [],
    token: { secret: 'shhhhh' }
  },
  idm: {
    host: 'keyrock.com',
    port: '3000',
    ssl: false
  },
  app: {
    host: 'fiware.org',
    port: '1026',
    ssl: false // Use true if the app server listens in https
  },
  organizations: {
    enabled: false
  },
  cache_time: 300,
  public_paths: ['/public'],
  authorization: {
    enabled: false,
    pdp: 'idm', // idm|iShare|xacml|authzforce|opa|azf
    header: undefined, // NGSILD-Tenant|fiware-service
    azf: {
      protocol: 'http',
      host: 'localhost',
      port: 8080,
      custom_policy: undefined // use undefined to default policy checks (HTTP verb + path).
    }
  }
};

describe('Authentication: JWT Token', () => {
  let pep;
  let contextBrokerMock;
  let idmMock;

  beforeEach((done) => {
    const app = require('../../app');
    pep = app.start_server('12345', config);
    nock.cleanAll();
    cache.flush();
    done();
  });

  afterEach((done) => {
    pep.close(config.pep_port);
    config.pep.secret = undefined;
    done();
  });

  describe('When a URL is requested and no JWT token is present', () => {
    it('should deny access', (done) => {
      got.get('restricted_path', request_no_jwt).then((response) => {
        should.equal(response.statusCode, StatusCodes.UNAUTHORIZED);
        done();
      });
    });
  });

  describe('When a public path is requested', () => {
    beforeEach(() => {
      contextBrokerMock = nock('http://fiware.org:1026').get('/public').reply(StatusCodes.OK, {});
    });
    it('should allow access', (done) => {
      got.get('public', request_with_jwt).then((response) => {
        contextBrokerMock.done();
        should.equal(response.statusCode, StatusCodes.OK);
        done();
      });
    });
  });

  describe('When a restricted path is requested with a legitimate JWT', () => {
    beforeEach(() => {
      contextBrokerMock = nock('http://fiware.org:1026').get('/restricted').reply(StatusCodes.OK, {});
    });
    it('should authenticate the user and allow access', (done) => {
      got.get('restricted', request_with_jwt).then((response) => {
        contextBrokerMock.done();
        should.equal(response.statusCode, StatusCodes.OK);
        done();
      });
    });
  });

  describe('When a restricted path is requested with an expired JWT', () => {
    beforeEach(async () => {
      await sleep(100);
    });
    it('should deny access', (done) => {
      got.get('restricted', request_with_expired_jwt).then((response) => {
        contextBrokerMock.done();
        should.equal(response.statusCode, StatusCodes.UNAUTHORIZED);
        done();
      });
    });
  });

  describe('When a restricted path is requested for an unrecognized JWT', () => {
    beforeEach(() => {
      idmMock = nock('http://keyrock.com:3000')
        .get('/user?access_token=' + invalid_token + '&app_id=application_id')
        .reply(StatusCodes.UNAUTHORIZED);
    });
    it('should fallback to Keyrock and deny access', (done) => {
      got.get('restricted', request_with_invalid_jwt).then((response) => {
        should.equal(response.statusCode, StatusCodes.UNAUTHORIZED);
        idmMock.done();
        done();
      });
    });
  });

  describe('When a non-existant restricted path is requested', () => {
    beforeEach(() => {
      contextBrokerMock = nock('http://fiware.org:1026').get('/restricted').reply(404);
    });
    it('should authenticate the user and proxy the error', (done) => {
      got.get('restricted', request_with_jwt).then((response) => {
        contextBrokerMock.done();
        should.equal(response.statusCode, 404);
        done();
      });
    });
  });
});
