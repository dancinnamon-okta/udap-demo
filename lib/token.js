'use strict';
const axios = require('axios')
const querystring = require('querystring')
const udap = require('./udap_util.js')

//Step 6- Token Proxy will take out the patient_id value in the token, and return it alongside the token instead.
//This is also where we handle public applications that need tokens.
module.exports.tokenHandler = async (tokenRequestBody, tokenRequestHeaders) => {
	const tokenEndpoint = process.env.OKTA_ORG_VANITY_URL_TOKEN_ENDPOINT

	console.log('Token proxy called.')
	console.log('Calling real /token endpoint at Okta.')

	//Get the proper Okta /token request based upon the situation.
	var inboundFormData = querystring.parse(tokenRequestBody)

	if(inboundFormData.udap) {
		try {
			var jwtAnt = inboundFormData.client_assertion
			var validatedJwtAnt = await validateJwtAnt(jwtAnt)
		}
		catch (ex) {
			console.error(ex)
			var returnBody = {
					'error' : ex.code,
					'error_description': ex.message
			}
			console.error("Return body:",returnBody)
			return {
					//400 - Bad Request
					statusCode: 400,
					body: returnBody
			}
		}
	}
	console.log("JWT Body:")
	console.log(validatedJwtAnt.body)
	var oktaFormData = await get_okta_token_request(inboundFormData, tokenRequestHeaders, validatedJwtAnt.body)

	console.log('Body to send to Okta:')
	console.log(oktaFormData)
	if(oktaFormData) {
		try {
			var oktaResponse = await axios.request({
				'url': tokenEndpoint,
				'method': 'POST',
				'headers': {'Content-Type': 'application/x-www-form-urlencoded', 'Host': process.env.BASE_DOMAIN},
				'data': oktaFormData
			})
			console.log('Response from Okta:')
			console.log(oktaResponse.data)
				return {
					statusCode: oktaResponse.status,
					body: oktaResponse.data
				}

		}
		catch(error) {
			console.log("Error while calling Okta:")
			console.log(error)
			if(error.isAxiosError) { //Error from Okta, or while calling Okta.
				return {
					statusCode: error.response.status,
					body: error.response.data
				}
			}
			else {
				throw error
			}

		}
	}
	else {
		return{
			statusCode: 400,
			body: 'An invalid token request was made.'
		}
	}
}

function get_okta_token_request(requestBody, requestHeaders, jwtBody) {
	//Pass the proper data to Okta that has been sent to the token proxy.
	var formBody = ''

	//Start off by putting in our grant_type, common to all requests.
	formBody = 'grant_type=' + requestBody.grant_type

	//Private Key JWT Authentication
	if(requestBody.client_assertion) {
			formBody += '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=' + requestBody.client_assertion
	}
	else {
		throw new Error("Only private_key_jwt client authentication is allowed on this authorization server.")
	}

	//If PKCE was used, pass that through.
	if(requestBody.code_verifier) {
		formBody += '&code_verifier=' + requestBody.code_verifier
	}

	//Add in the authz code and redirect_uri if that's the situation we're in.
	if(requestBody.code) {
		formBody += '&code=' + requestBody.code +
			'&redirect_uri=' + requestBody.redirect_uri
	}

	if(requestBody.scope) {
		formBody += '&scope=' + requestBody.scope
	}

	if(requestBody.refresh_token) {
		formBody += '&refresh_token=' + requestBody.refresh_token
	}

	if(requestBody.udap) {
		formBody += '&udap=' + requestBody.udap
	}

	return formBody
}

async function validateJwtAnt(jwtAnt)
{
    try{
        var verifiedJwtAnt = await udap.validateJwtWithCertChain(jwtAnt)
        validateUdapProperties(verifiedJwtAnt.body)
        return verifiedJwtAnt
    }
    catch (ex)
    {
        console.error("Error validating JwtAnt:")
        console.error(ex)
        var error = new Error()
        if (ex.code = 'invalid_software_statement')
        {
            error.code = 'invalid_request'
        }
        else if (ex.code = 'unapproved_software_statement')
        {
            error.code = 'invalid_client'
        }
        error.message = ex.message
        throw error
    }

}

function validateUdapProperties(jwtAntBody)
{
    var error = new Error()
    var d = new Date()
    error.code = 'invalid_request'
    if (!jwtAntBody.hasOwnProperty('exp') || jwtAntBody.exp == '' ||
    (jwtAntBody.exp*1000 <= d.getTime()) || (jwtAntBody.exp - jwtAntBody.iat)>300)
    {
        error.message = 'Invalid exp value'
        console.error(error)
        throw error
    }
    if (jwtAntBody.hasOwnProperty('client_id') && jwtAntBody.client_id != jwtAntBody.sub)
    {
        error.message = 'Invalid client_id or sub value'
        console.error(error)
        throw error
    }
    console.log("aud: "+ jwtAntBody.aud)
    console.log('expected aud: ' + process.env.EXTERNAL_TOKEN_ENDPOINT)
    if (!jwtAntBody.hasOwnProperty('aud') || jwtAntBody.aud  == '' || jwtAntBody.aud != process.env.EXTERNAL_TOKEN_ENDPOINT)
    {
        error.message = 'Invalid aud value'
        console.error(error)
        throw error
    }
}
