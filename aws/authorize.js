'use strict';
const authorizeLib = require('../lib/authorize')

//Authorize endpoint - AWS implementation.
//See the authorize library for full details.
module.exports.authorizeHandler = async (event, context) => {
	var authorizeResult = await authorizeLib.authorizeHandler(event.queryStringParameters, event.headers)
	return {
		statusCode: authorizeResult.statusCode,
		headers: authorizeResult.headers,
		body: JSON.stringify(authorizeResult.body)
	}
}
