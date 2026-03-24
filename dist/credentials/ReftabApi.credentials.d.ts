import type { ICredentialType, INodeProperties, ICredentialTestRequest, ICredentialDataDecryptedObject, IHttpRequestOptions } from 'n8n-workflow';
export declare class ReftabApi implements ICredentialType {
    name: string;
    displayName: string;
    icon: "file:reftab.svg";
    documentationUrl: string;
    properties: INodeProperties[];
    authenticate(credentials: ICredentialDataDecryptedObject, requestOptions: IHttpRequestOptions): Promise<IHttpRequestOptions>;
    test: ICredentialTestRequest;
}
