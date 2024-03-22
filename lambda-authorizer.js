import http from 'http';

export const handler = async (event) => {
    var headers = event.headers;
  

    if (!event.headers || !event.headers.Authorization) {
        return {
            statusCode: 401,
            body: JSON.stringify('Token de autorização ausente.'),
        };
    }

    const tokenWithBearer =  event.headers.Authorization;
    const API_ENDPOINT = 'http://a387dd5316db84c359158d13a88247ae-965976261.us-east-1.elb.amazonaws.com';

    const options = {
        hostname: API_ENDPOINT,
        port: 8080,
        path: `/autenticacao/validar/${encodeURIComponent(tokenWithBearer)}`,
        method: 'GET',
    };

console.log('Solicitação:', options);
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(generatePolicy('user', 'Allow', event.methodArn));
                } else {
                    resolve(generatePolicy('user', 'Deny', event.methodArn));
                }
            });
        });

        req.on('error', (error) => {
            console.error('Ocorreu um erro ao validar token:', error);
            resolve(generatePolicy('user', 'Deny', event.methodArn));
        });

        req.end();
    });
};

const generatePolicy = (principalId, effect, resource) => {
    const authResponse = {
        principalId: principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: effect,
                    Resource: resource,
                },
            ],
        },
    };
    return authResponse;
};
