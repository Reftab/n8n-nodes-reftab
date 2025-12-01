import {
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

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
}
