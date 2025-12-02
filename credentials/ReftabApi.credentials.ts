import type {
	ICredentialType,
	INodeProperties,
	ICredentialTestRequest,
	ICredentialDataDecryptedObject,
	IHttpRequestOptions,
} from 'n8n-workflow';
import * as crypto from 'crypto';

export class ReftabApi implements ICredentialType {
	name = 'reftabApi';
	displayName = 'Reftab API';
	documentationUrl = 'https://reftab.com/api-docs';
	properties: INodeProperties[] = [
		{
			displayName: 'Public Key',
			name: 'publicKey',
			type: 'string',
			default: '',
			required: true,
			description: 'Your Reftab API public key',
		},
		{
			displayName: 'Secret Key',
			name: 'secretKey',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'Your Reftab API secret key',
		},
	];

	async authenticate(
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const publicKey = credentials.publicKey as string;
		const secretKey = credentials.secretKey as string;
		const now = new Date().toUTCString();
		const method = requestOptions.method || 'GET';
		const baseURL = requestOptions.baseURL || 'https://www.reftab.com/api';
    const urlPath = requestOptions.url as string;
    const url = urlPath.startsWith('http') ? urlPath : `${baseURL}${urlPath}`;

		let contentMD5 = '';
		let contentType = '';

		if (requestOptions.body && (method === 'POST' || method === 'PUT')) {
			const bodyString = typeof requestOptions.body === 'string' 
				? requestOptions.body 
				: JSON.stringify(requestOptions.body);
			contentMD5 = crypto.createHash('md5').update(bodyString).digest('base64');
			contentType = 'application/json';
		}

		const signatureString = `${method}\n${contentMD5}\n${contentType}\n${now}\n${url}`;
		const hmac = crypto.createHmac('sha256', secretKey);
		hmac.update(signatureString);
		const hexDigest = hmac.digest('hex');
		const signature = Buffer.from(hexDigest).toString('base64');

		requestOptions.headers = {
			...requestOptions.headers,
			'Authorization': `RT ${publicKey}:${signature}`,
			'x-rt-date': now,
		};

		if (contentType) {
			requestOptions.headers['Content-Type'] = contentType;
		}

		return requestOptions;
	}

	test: ICredentialTestRequest = {
		request: {
			baseURL: 'https://www.reftab.com/api',
			url: '/locations',
			method: 'GET',
		},
	};
}