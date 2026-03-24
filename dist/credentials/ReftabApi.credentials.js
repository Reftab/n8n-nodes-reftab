"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ReftabApi = void 0;
const crypto = __importStar(require("crypto"));
class ReftabApi {
    constructor() {
        this.name = 'reftabApi';
        this.displayName = 'Reftab API';
        this.documentationUrl = 'https://reftab.com/api-docs';
        this.properties = [
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
        this.test = {
            request: {
                baseURL: 'https://www.reftab.com/api',
                url: '/locations',
                method: 'GET',
            },
        };
    }
    async authenticate(credentials, requestOptions) {
        const publicKey = credentials.publicKey;
        const secretKey = credentials.secretKey;
        const now = new Date().toUTCString();
        const method = requestOptions.method || 'GET';
        const baseURL = requestOptions.baseURL || 'https://www.reftab.com/api';
        const urlPath = requestOptions.url;
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
}
exports.ReftabApi = ReftabApi;
