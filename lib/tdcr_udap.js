'use strict'
const axios = require('axios')
const udap = require('./udap_util.js')


//Dynamic Client Registration Proxy
module.exports.clientRegistrationHandler = async (clientRegisterRequestBody, clientRegisterRequestHeaders) => {
  //We're going to use the /apps API, not clients.
  const oktaAppsEndpoint = 'https://' + process.env.OKTA_ORG + '/api/v1/apps'
  console.log('Register endpoint called.')
  console.log('Validating signed software statement')
  console.log("Client request body:")
  console.log(clientRegisterRequestBody)


  const inboundSoftwareStatement = JSON.parse(clientRegisterRequestBody).software_statement

  console.log('Software Statement:')
  console.log(inboundSoftwareStatement)

  var validatedSoftwareStatementJWT = null
  //Validate the proper UDAP signed software token.
  try {
    validatedSoftwareStatementJWT = await validateUdapSoftwareStatement(inboundSoftwareStatement)
  }
  catch (ex) {
    //At this point we can get a few different types of errors- so let's just parrot out the internal exception.
      console.error("validateUdapSoftwareStatement Exception:")
      console.error(ex)
      const returnBody = {
          'error' : ex.code,
          'error_description': ex.message
      }
      return {
          //400 - Bad Request
          statusCode: 400,
          body: returnBody
      }
  }

  var oktaClientRegJson = convertJwtToOktaJson(validatedSoftwareStatementJWT)
	console.log("Body to send to Okta Client Registration")
	console.log(JSON.stringify(oktaClientRegJson))

	try {
    const oktaAPIToken = await udap.getOktaAPIToken(process.env.OKTA_CLIENT_TOKEN_ENDPOINT, process.env.OKTA_CLIENT_ID, process.env.OKTA_PRIVATE_KEY_FILE)
		const oktaResponse = await axios.request({
			'url': oktaAppsEndpoint,
			'method': 'POST',
			'headers': {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + oktaAPIToken
      },
			'data': oktaClientRegJson
		})
		console.log('Response from Okta:')
		console.log(JSON.stringify(oktaResponse.data))

    const dcrReturn = {
      "client_id": oktaResponse.data.credentials.oauthClient.client_id,
      "software_statement": inboundSoftwareStatement,
      ...validatedSoftwareStatementJWT.body  //merge in the details from the validated software statement JWT.
    }
    console.log('Response to client')
    console.log(JSON.stringify(dcrReturn))
    return {
        statusCode: 201,
        body: dcrReturn
    }
	}
	catch (error) {
		console.error("Error while registering with Okta:")
		console.error(error)
		return {
			statusCode: 400,
			body: {
        'error': 'unknown_error',
        'error_description': error.response.data
      }
		}
	}
}

async function validateUdapSoftwareStatement(inboundSoftwareStatement) {
	//TODO:  Validate Client software statement
	// 1 validate signature using public key from x5c parameter in JOSE header
	// 2 Validate/Construct certificate chain
	// 3 Validate the software statement
	//  iss, sub, aud, exp, iat, jti values in software statement
	// 		iss must match uriName in the Subject Alternative Names extension of client certificate.
	//      sub value must match iss value
	//		aud value must contain the Auhtorization Server's registration endpoint URL
	//      Software statement must be unexpired

    /*
    Errors Defined here:
        https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2

    RFC 7591 Error codes
      invalid_redirect_uri
      The value of one or more redirection URIs is invalid.

   invalid_client_metadata
      The value of one of the client metadata fields is invalid and the
      server has rejected this request.  Note that an authorization
      server MAY choose to substitute a valid value for any requested
      parameter of a client's metadata.

   invalid_software_statement
      The software statement presented is invalid.

   unapproved_software_statement
      The software statement presented is not approved for use by this
      authorization server.
    */
	var ssVerifiedJwt = null

  console.log('Software Statement:')
  console.log(inboundSoftwareStatement)

	ssVerifiedJwt = await udap.validateJwtWithCertChain(inboundSoftwareStatement)

  //UDAP Specific properties validation
  console.log('JWT Body to validate:')
  console.log(ssVerifiedJwt.body)
  validateSignedSoftwareBody(ssVerifiedJwt.body)

  return ssVerifiedJwt
}

function validateSignedSoftwareBody(ssJwtBody) {
  var error = new Error()
  error.code = 'invalid_software_statement'


  //nJWT verifier will validate this.
	if (!ssJwtBody.hasOwnProperty('sub') || !ssJwtBody.hasOwnProperty('iss') ||
        ssJwtBody.iss != ssJwtBody.sub || ssJwtBody.iss == "" || ssJwtBody.sub == "")
  {
    error.message = 'Invalid iss/sub values'
    console.error(error)
    throw error
	}

  //TODO:  Should we call the UDAP meta data to get reg endpoint?
  //We need to ensure the aud is set properly.
  if (ssJwtBody.aud == "" || ssJwtBody.aud != process.env.GATEWAY_URL + '/register')
  {
    error.message = 'Invalid aud value||'
    console.error(error)
    throw error
  }

  var d = new Date()
  console.log("IAT: " + (ssJwtBody.iat * 1000) + " Current Value: " + d.getTime())
  if (!ssJwtBody.hasOwnProperty('iat') || ssJwtBody.iat == "" || (ssJwtBody.iat * 1000) >= d.getTime())
  {
    error.message = 'Invalid iat value'
    throw error
  }

  if (!ssJwtBody.hasOwnProperty('exp') || ssJwtBody.exp == "" ||
  (ssJwtBody.exp*1000 <= d.getTime()) || (ssJwtBody.exp - ssJwtBody.iat)>300)
  {
    error.message = 'Invalid exp value'
    console.error(error)
    throw error
  }

  ssJwtBody = checkClientMetaData(ssJwtBody)
	return ssJwtBody
}

function checkClientMetaData(ssJwtBody)
{
  console.log('Checking client metadata')
  var error = new Error()
  error.code = 'invalid_client_metadata'

  if (!ssJwtBody.hasOwnProperty('client_name') || ssJwtBody.client_name == '')
  {
    error.message = 'Missing client_name'
    console.error(error)
    throw error
  }

  if (!ssJwtBody.hasOwnProperty('grant_types') || ssJwtBody.grant_types == '')
  {
    error.message = 'Missing grant_types'
    console.error(error)
    throw error
  }

  console.log('Grant Types inlcudes authorization_code: ')
  console.log(ssJwtBody.grant_types)

  if ((!ssJwtBody.hasOwnProperty('redirect_uris') || ssJwtBody.redirect_uris == '') && (ssJwtBody.grant_types.includes('authorization_code')))
  {
    error.message = 'Missing redirect_uris'
    console.error(error)
    throw error
  }

  if ((!ssJwtBody.hasOwnProperty('response_types') || ssJwtBody.response_types == '') && (ssJwtBody.grant_types.includes('authorization_code')))
  {
    error.message = 'Missing response_types'
    console.error(error)
    throw error
  }

  if (!ssJwtBody.hasOwnProperty('token_endpoint_auth_method') || ssJwtBody.token_endpoint_auth_method == '')
  {
    error.message = 'Missing token_endpoint_auth_method'
    console.error(error)
    throw error
  }
  return ssJwtBody
}

function convertJwtToOktaJson(ssVerifiedJwtObject) {
  console.log("Validated UDAP JWT")
  console.log(ssVerifiedJwtObject)

  var oktaClientRegJson = {
    'name': 'oidc_client',
    'label': ssVerifiedJwtObject.body.client_name,
    'signOnMode': 'OPENID_CONNECT',
    'credentials': {
      'oauthClient': {
        'token_endpoint_auth_method': 'private_key_jwt'
      }
    },
    'settings': {
      'implicitAssignment': true,
      'oauthClient': {
        'redirect_uris': ssVerifiedJwtObject.body.redirect_uris,
        'response_types': ssVerifiedJwtObject.body.response_types,
        'application_type':(ssVerifiedJwtObject.body.grant_types.includes('authorization_code') ? 'web' : 'service'),
        'grant_types' : ssVerifiedJwtObject.body.grant_types,
        'jwks': udap.getPublicKeyJWKS(ssVerifiedJwtObject),
        'consent_method': 'TRUSTED'
      }
    },
    'profile': {
      'implicitAssignment': true
    }
  }
  return oktaClientRegJson
}
