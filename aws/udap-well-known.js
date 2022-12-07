'use strict';
const udapWellKnownLib = require('../lib/udap-well-known.js')

//Metadata endpoints - AWS Lambda Interface
module.exports.udapConfigHandler = async (event, context) => {
	var udapConfigResult = await udapWellKnownLib.getUDAPConfiguration()
	return {
		statusCode: 200,
		body: JSON.stringify(udapConfigResult),
		headers: {
			'Access-Control-Allow-Origin': '*', // CORS
			'Access-Control-Allow-Credentials': false // Required for cookies, authorization headers with HTTPS
		}
	}
}
