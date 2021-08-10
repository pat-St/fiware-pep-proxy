/*
 * Copyright 2021 -  Universidad Politécnica de Madrid.
 *
 * This file is part of PEP-Proxy
 *
 */

const got = require('got');
const should = require('should');
const nock = require('nock');
const cache = require('../../lib/cache');

const ngsiPayload = [
  {
    id: 'urn:ngsi-ld:TemperatureSensor:002',
    type: 'TemperatureSensor',
    category: {
      type: 'Property',
      value: 'sensor'
    },
    temperature: {
      type: 'Property',
      value: 21,
      unitCode: 'CEL'
    }
  },
  {
    id: 'urn:ngsi-ld:TemperatureSensor:003',
    type: 'TemperatureSensor',
    category: {
      type: 'Property',
      value: 'sensor'
    },
    temperature: {
      type: 'Property',
      value: 27,
      unitCode: 'CEL'
    }
  }
];
const keyrock_user_response = {
  app_id: 'application_id',
  trusted_apps: [],
  roles: [
    {
      id: 'managers-role-0000-0000-000000000000',
      name: 'Management'
    }
  ]
};

const request_with_headers = {
  prefixUrl: 'http:/localhost:80',
  throwHttpErrors: false,
  headers: { 'x-auth-token': '111111111', 'fiware-service': 'smart-gondor', 'x-forwarded-for': 'example.com' }
};
const request_with_headers_and_body = {
  prefixUrl: 'http:/localhost:80',
  throwHttpErrors: false,
  headers: { 'x-auth-token': '111111111', 'fiware-service': 'smart-gondor' },
  json: ngsiPayload
};

const open_policy_agent_permit_response = 'true';
const open_policy_agent_deny_response = 'false';

const config = {
  pep_port: 80,
  pep: {
    app_id: 'application_id',
    trusted_apps: []
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
  public_paths: [],
  authorization: {
    enabled: true,
    pdp: 'opa', // idm|iShare|xacml|authzforce|opa|azf
    header: 'fiware-service',
    opa: {
      protocol: 'http',
      host: 'openpolicyagent.com',
      port: 8080
    }
  }
};

describe('Authorization: Open Policy Agent PDP', function () {
  let pep;
  let contextBrokerMock;
  let idmMock;
  let openPolicyAgentMock;

  beforeEach(function (done) {
    const app = require('../../app');
    pep = app.start_server('12345', config);
    cache.flush();
    nock.cleanAll();
    idmMock = nock('http://keyrock.com:3000')
      .get('/user?access_token=111111111&app_id=application_id')
      .reply(200, keyrock_user_response);
    done();
  });

  afterEach(function (done) {
    pep.close(config.pep_port);
    done();
  });

  describe('When a restricted URL is requested by a legitimate user', function () {
    beforeEach(function () {
      contextBrokerMock = nock('http://fiware.org:1026').get('/path/entities/urn:ngsi-ld:entity:1111').reply(200, {});
      openPolicyAgentMock = nock('http://openpolicyagent.com:8080')
        .post('/query')
        .reply(200, open_policy_agent_permit_response);
    });

    it('should allow access', function (done) {
      got.get('path/entities/urn:ngsi-ld:entity:1111', request_with_headers).then((response) => {
        contextBrokerMock.done();
        idmMock.done();
        openPolicyAgentMock.done();
        should.equal(response.statusCode, 200);
        done();
      });
    });
  });

  describe('When a restricted URL is requested by a forbidden user', function () {
    beforeEach(function () {
      openPolicyAgentMock = nock('http://openpolicyagent.com:8080')
        .post('/query')
        .reply(200, open_policy_agent_deny_response);
    });

    it('should deny access', function (done) {
      got.get('path/entities/urn:ngsi-ld:entity:1111', request_with_headers).then((response) => {
        idmMock.done();
        openPolicyAgentMock.done();
        should.equal(response.statusCode, 401);
        done();
      });
    });
  });

  describe('When a restricted URL with a query string is requested', function () {
    beforeEach(function () {
      contextBrokerMock = nock('http://fiware.org:1026')
        .get('/path/entities/?ids=urn:ngsi-ld:entity:1111&type=entity')
        .reply(200, {});
      openPolicyAgentMock = nock('http://openpolicyagent.com:8080')
        .post('/query')
        .reply(200, open_policy_agent_permit_response);
    });

    it('should allow access based on entities', function (done) {
      got.get('path/entities/?ids=urn:ngsi-ld:entity:1111&type=entity', request_with_headers).then((response) => {
        contextBrokerMock.done();
        idmMock.done();
        openPolicyAgentMock.done();
        should.equal(response.statusCode, 200);
        done();
      });
    });
  });

  describe('When a restricted URL with a payload body is requested', function () {
    beforeEach(function () {
      openPolicyAgentMock = nock('http://openpolicyagent.com:8080')
        .post('/query')
        .reply(200, open_policy_agent_permit_response);
      contextBrokerMock = nock('http://fiware.org:1026').patch('/path/entityOperations/upsert').reply(200, {});
    });

    it('should allow access based on entities', function (done) {
      got.patch('path/entityOperations/upsert', request_with_headers_and_body).then((response) => {
        contextBrokerMock.done();
        idmMock.done();
        openPolicyAgentMock.done();
        should.equal(response.statusCode, 200);
        done();
      });
    });
  });
});
