'use strict';
const axios = require('axios');
//CSR ID FOR CONNECTATHON! oiah2ZoSgnuZUCKuKwzBAdmCms9kL8xnnQ-gMGoQ60M

//Look up IDP by URL from Okta in the IDP list (maybe a cache or something too)
//If found, simply forward the request on to Okta, replacing the URL with the IDP ID.

//If NOT found, retrieve the UDAP metadata from the IDP, and validate.  If valid, then create a new IDP in Okta, and then forward the request on to Okta.

//First cut, just assume the IDP is in Okta to start (we can create one manually), and then add the create in afterward.

module.exports.authorizeHandler = async (requestQuerystring) => {

	//Cache Client_id, state, scopes, redirect_uri into a signed cookie
	var inboundRequest = {
		client_id: requestQuerystring.client_id,
		state: requestQuerystring.state,
		scope: requestQuerystring.scope.split(' '),
		redirect_uri: requestQuerystring.redirect_uri,
		code_challenge: requestQuerystring.code_challenge,
		code_challenge_method: requestQuerystring.code_challenge_method
	};

	//Validate the "aud" parameter as part of the SMART launch framework requirements. If it's not included, or it's not matching the our audience value, reject the request.
	var audParam = requestQuerystring.aud.replace(/([//])$/g, '');
	if(!audParam || audParam !== process.env.EXPECTED_AUD_VALUE.replace(/([//])$/g, '')) {
		console.log('An invalid audience was specified on the authorize request.');
		console.log('Required aud:' + process.env.EXPECTED_AUD_VALUE)
		console.log('Actual Aud:' + audParam)
		return {
			statusCode: 400,
			body: 'An invalid audience was specified on the authorize request.',
			location: null,
			origRequestCookie: null,
			pickerAuthzCookie: null
		}
	}

	try {
		var validationResponse = await validateRedirectURL(requestQuerystring.client_id, requestQuerystring.redirect_uri)
	}
	catch(validationError) {
		console.log(validationError)
		return {
			statusCode: 400,
			body: 'Unable to validate the redirect_uri passed in.',
			location: null,
			origRequestCookie: null,
			pickerAuthzCookie: null
		}
	}
	console.log('Inbound data to be cached off for later:');
	console.log(inboundRequest);

	var origRequestCookieSigned = cookieSignature.sign(JSON.stringify(inboundRequest), process.env.STATE_COOKIE_SIGNATURE_KEY)

	var pickerAuthzState = uuidv4();

	//For the picker app to properly validate the OAuth2 state we need to cache that off in a signed cookie as well.
	var pickerAuthzStateCookieSigned = cookieSignature.sign(pickerAuthzState, process.env.STATE_COOKIE_SIGNATURE_KEY)

	//Build person picker authz request
	var picker_auth_url = process.env.PICKER_ISSUER + '/v1/authorize' +
		'?client_id=' +
		process.env.PICKER_CLIENT_ID +
		'&response_type=code&scope=openid%20profile%20email&redirect_uri=' +
		process.env.GATEWAY_URL + '/picker_oidc_callback' +
		'&state=' +
		pickerAuthzState;

	console.log('Redirecting the user to: ' + picker_auth_url);
	return {
		statusCode: 302,
		location: picker_auth_url,
		body: null,
		origRequestCookie: origRequestCookieSigned,
		pickerAuthzCookie: pickerAuthzStateCookieSigned
	}
}
