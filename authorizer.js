const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: '2012-10-17', // default version
    Statement: [
      {
        Action: 'execute-api:Invoke', // default action
        Effect: effect,
        Resource: resource,
      },
    ],
  };
  return policyDocument;
};

const getToken = (event) => {
  if (!event.type || event.type !== 'REQUEST') {
    throw new Error('Expected "event.type" parameter to have value "REQUEST"');
  }

  const tokenString = event.headers?.authorization;
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set');
  }

  const match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`
    );
  }
  return match[1];
};

const authenticate = async (event) => {
  const token = getToken(event);
  return {
    principalId: 'foo.bar',
    policyDocument: getPolicyDocument('Allow', event.routeArn),
    context: { scope: 'decoded.scope' },
  };
};

module.exports.handler = async (event) => {
  console.log('event', event);
  try {
    const policy = await authenticate(event);
    return policy;
  } catch (err) {
    console.log('Error', err);
    return {
      principalId: 'foo.bar',
      policyDocument: getPolicyDocument('Deny', event.routeArn),
      context: { Error: err },
    };
  }
};
