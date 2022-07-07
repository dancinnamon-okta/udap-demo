'use strict';
const tdcr_udapLib = require('../lib/tdcr_udap')

//Trusted Dynamic Client Registration Proxy for standard OAuth DCR
//See the tdcr_udap library for full documentation.
module.exports.clientRegistrationHandler = async (event, context) => {
	var handlerResponse = await tdcr_udapLib.clientRegistrationHandler(event.body, event.headers)
	return {
		statusCode: handlerResponse.statusCode,
		body: JSON.stringify(handlerResponse.body),
		headers: {"Cache-Control": "no-store", "Pragma": "no-cache"}
	}
}
