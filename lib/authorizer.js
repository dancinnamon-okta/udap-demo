'use strict'

//This is our authorizer that our FHIR server will use in two scenarios.
//Initial member match- the token must be valid and must have the system/patient.s scope.
//Final user get- the token must be valid, must have the system/patient.r scope, and contain the match context ID within it.
const njwt = require('njwt');
const AuthPolicy = require('./auth-policy');
const jwk2pem = require('pem-jwk').jwk2pem
const axios = require('axios');

const authzKeysEndpoint = process.env.AUTHZ_ISSUER + '/v1/keys'

exports.handler = async function(event, context) {
  //Parse out the inbound request to get what we need for validation and output.
  var apiOptions = {};
  const arnParts = event.methodArn.split(':');
  const apiGatewayArnPart = arnParts[5].split('/');
  const awsAccountId = arnParts[4];
  apiOptions.region = arnParts[3];
  apiOptions.restApiId = apiGatewayArnPart[0];
  apiOptions.stage = apiGatewayArnPart[1];
  const method = apiGatewayArnPart[2];
  console.log("Inbound event")
  console.log(JSON.stringify(event))
  //First token validation.
  var verifiedJWT = null;

  try {
    var key = await getSigningKey()
    var arr = event.authorizationToken.split(" ");
    var access_token = arr[1];
    

    var signingKeyPem = jwk2pem(key)
    verifiedJWT = njwt.verify(access_token, signingKeyPem, "RS256")
  }
  catch(err) {
    console.log("An invalid JWT was passed in.  The request is not authorized.")
    console.log(err)
    const failPolicy = new AuthPolicy('none', awsAccountId, apiOptions);
    failPolicy.denyAllMethods()
    return context.succeed(failPolicy.build());
  }

  //JWT is validated. Let's go one level lower. This is really only setup for patient reading right now.

  //Define our policy header.
  const policy = new AuthPolicy(verifiedJWT.body.sub, awsAccountId, apiOptions);

  //Our rules here below.

  //If we have patient/patient.s or patient/patient.r, then we allow access to the patient in the JWT.
  if(method == 'GET' && verifiedJWT.body.scp.includes('patient/Patient.r')) {
    //Here, we can trust the patient id in the JWT.
    var allowedURL = "/" + verifiedJWT.body.fhirUser

    policy.allowMethod(AuthPolicy.HttpVerb.GET, allowedURL);

  }

  //Going to allow all patient access for B2B tokens.
  if(method == 'GET' && verifiedJWT.body.scp.includes('system/Patient.r')) {
    //Here, we can trust the patient id in the JWT.
    var allowedURL = "/Patient/*"

    policy.allowMethod(AuthPolicy.HttpVerb.GET, allowedURL);

  }


  if(policy.allowMethods.length == 0) {
    policy.denyAllMethods()
  }

  return context.succeed(policy.build());
}

async function getSigningKey() {
  try {
    var keysResponse = await axios.request({
      'url': authzKeysEndpoint,
      'method': 'get'
    })
    console.log('Keys response')
    console.log(keysResponse.data)
    return keysResponse.data.keys[0]
  }
  catch(error) {
    console.log(error)
    throw new Error("Error getting keys...")
  }
}
