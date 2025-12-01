import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IDataObject,
	NodeOperationError,
	IHttpRequestOptions,
	ILoadOptionsFunctions,
	INodePropertyOptions,
	ICredentialTestFunctions,
	ICredentialsDecrypted,
	INodeCredentialTestResult,
} from 'n8n-workflow';
import * as crypto from "crypto";

/**
 * Generate HMAC signature for Reftab API
 *
 * Based on the official Reftab Postman script and verified against CryptoJS behavior:
 * - signatureToSign = METHOD\nContentMD5\nContentType\nDate\nURL
 * - HMAC-SHA256 is computed and the HEX result is then Base64 encoded
 * - This matches: btoa(CryptoJS.HmacSHA256(signatureToSign, secretKey).toString())
 */
function generateHmacSignature(
  method: string,
  url: string,
  body: string | undefined,
  secretKey: string,
): { authorization: string; date: string } {
  const now = new Date().toUTCString();
  let contentMD5 = "";
  let contentType = "";

  // Only compute MD5 and set content-type for POST/PUT with body
  if (body && (method === "POST" || method === "PUT")) {
    contentMD5 = crypto.createHash("md5").update(body).digest("hex");
    contentType = "application/json";
  }

  // Build signature string according to Reftab API spec
  // Format: METHOD\nContentMD5\nContentType\nDate\nURL
  const signatureString = `${method}\n${contentMD5}\n${contentType}\n${now}\n${url}`;

  // Generate HMAC-SHA256
  const hmac = crypto.createHmac("sha256", secretKey);
  hmac.update(signatureString);

  // CryptoJS's btoa() on HmacSHA256 result converts the HEX STRING to base64
  // So we need: base64(hex_string), not base64(binary_digest)
  const hexDigest = hmac.digest("hex");
  const signature = Buffer.from(hexDigest).toString("base64");

  return {
    authorization: signature,
    date: now,
  };
}

/**
 * Make authenticated request to Reftab API
 */
async function makeReftabRequest(
  context: IExecuteFunctions,
  method: string,
  endpoint: string,
  body?: IDataObject,
): Promise<IDataObject | IDataObject[]> {
  const credentials = await context.getCredentials("reftabApi");
  const publicKey = credentials.publicKey as string;
  const secretKey = credentials.secretKey as string;
  const baseUrl = "https://www.reftab.com/api";

  // Construct full URL - ensure no double slashes
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint.slice(1) : endpoint;
  const fullUrl = `${baseUrl}/${cleanEndpoint}`;

  // Stringify body if present - this exact string is used for MD5 hash
  const bodyString = body ? JSON.stringify(body) : undefined;

  // Generate HMAC signature using the full URL
  const { authorization, date } = generateHmacSignature(
    method,
    fullUrl,
    bodyString,
    secretKey,
  );

  // Build request options
  const options: IHttpRequestOptions = {
    method: method as "GET" | "POST" | "PUT" | "DELETE",
    url: fullUrl,
    headers: {
      Authorization: `RT ${publicKey}:${authorization}`,
      "x-rt-date": date,
    },
    ignoreHttpStatusErrors: true, // Don't throw on 4xx/5xx, let us handle it
    returnFullResponse: true, // Get full response including status code
  };

  // Add Content-Type and body for POST/PUT requests
  if ((method === "POST" || method === "PUT") && bodyString) {
    options.headers!["Content-Type"] = "application/json";
    // Send the exact same string we used for MD5 hash
    options.body = bodyString;
    // Don't use json: true since we're sending a pre-serialized string
  }

  try {
    const fullResponse = (await context.helpers.httpRequest(options)) as {
      body: unknown;
      headers: Record<string, string>;
      statusCode: number;
    };

    // Check for error status codes
    if (fullResponse.statusCode >= 400) {
      let errorMessage = "";
      const body = fullResponse.body;

      if (typeof body === "string") {
        try {
          const parsed = JSON.parse(body);
          errorMessage =
            parsed.message ||
            parsed.error ||
            parsed.msg ||
            parsed.reason ||
            body;
        } catch {
          errorMessage = body;
        }
      } else if (typeof body === "object" && body !== null) {
        const bodyObj = body as Record<string, unknown>;
        errorMessage = String(
          bodyObj.message ||
            bodyObj.error ||
            bodyObj.msg ||
            bodyObj.reason ||
            JSON.stringify(body),
        );
      }

      throw new Error(
        `Reftab API Error (${fullResponse.statusCode}): ${errorMessage || "Request failed"}`,
      );
    }

    // Success - parse and return body
    const responseBody = fullResponse.body;
    if (typeof responseBody === "string") {
      try {
        return JSON.parse(responseBody) as IDataObject | IDataObject[];
      } catch {
        return { data: responseBody } as IDataObject;
      }
    }
    return responseBody as IDataObject | IDataObject[];
  } catch (error: unknown) {
    // Re-throw our custom errors
    if (
      error instanceof Error &&
      error.message.startsWith("Reftab API Error")
    ) {
      throw error;
    }

    // Handle unexpected errors
    const anyError = error as Record<string, unknown>;
    const message = anyError.message || "Unknown error occurred";
    throw new Error(`Reftab API Error: ${message}`);
  }
}

/**
 * Deep merge two objects - updates target with source values
 */
function deepMerge(target: IDataObject, source: IDataObject): IDataObject {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (
      source[key] !== null &&
      typeof source[key] === "object" &&
      !Array.isArray(source[key]) &&
      target[key] !== null &&
      typeof target[key] === "object" &&
      !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(
        target[key] as IDataObject,
        source[key] as IDataObject,
      );
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

/**
 * PUT request with automatic GET-merge-PUT pattern
 * Reftab requires the full object for PUT requests
 */
async function makeReftabPutRequest(
  context: IExecuteFunctions,
  endpoint: string,
  updates: IDataObject,
): Promise<IDataObject | IDataObject[]> {
  // First GET the current object
  const current = (await makeReftabRequest(
    context,
    "GET",
    endpoint,
  )) as IDataObject;

  // Merge updates into current object
  const merged = deepMerge(current, updates);

  // PUT the merged object back
  return await makeReftabRequest(context, "PUT", endpoint, merged);
}

/**
 * Look up loanee by email and return the loanee ID (lnid) or user ID (loan_uid)
 */
async function lookupLoaneeByEmail(
  context: IExecuteFunctions,
  email: string,
): Promise<{ lnid?: number; loan_uid?: number }> {
  // Search for loanee by email
  const response = await makeReftabRequest(
    context,
    "GET",
    `loanees?q=${encodeURIComponent(email)}&limit=50`,
  );

  // Handle nested array structure [[...]]
  let loanees = response;
  if (
    Array.isArray(response) &&
    response.length > 0 &&
    Array.isArray(response[0])
  ) {
    loanees = response[0];
  }

  const loaneeArray = Array.isArray(loanees) ? loanees : [];

  // Find exact email match
  for (const loanee of loaneeArray) {
    const loaneeObj = loanee as Record<string, unknown>;
    if (String(loaneeObj.email || "").toLowerCase() === email.toLowerCase()) {
      // Check if it's a user (has uid) or loanee (has lnid)
      if (loaneeObj.uid) {
        return { loan_uid: Number(loaneeObj.uid) };
      } else if (loaneeObj.lnid) {
        return { lnid: Number(loaneeObj.lnid) };
      }
    }
  }

  throw new Error(`Loanee with email "${email}" not found`);
}

/**
 * Look up user by email and return the user ID (uid)
 * Uses the loanees endpoint which includes both users and loanees
 */
async function lookupUserByEmail(
  context: IExecuteFunctions,
  email: string,
): Promise<number> {
  // Search for user by email using loanees endpoint
  const response = await makeReftabRequest(
    context,
    "GET",
    `loanees?q=${encodeURIComponent(email)}&limit=50`,
  );

  // Handle nested array structure [[...]]
  let loanees = response;
  if (
    Array.isArray(response) &&
    response.length > 0 &&
    Array.isArray(response[0])
  ) {
    loanees = response[0];
  }

  const loaneeArray = Array.isArray(loanees) ? loanees : [];

  // Find exact email match - prefer users (with uid)
  for (const loanee of loaneeArray) {
    const loaneeObj = loanee as Record<string, unknown>;
    if (String(loaneeObj.email || "").toLowerCase() === email.toLowerCase()) {
      // For maintenance assignment, we need the uid (user ID)
      if (loaneeObj.uid) {
        return Number(loaneeObj.uid);
      }
    }
  }

  throw new Error(
    `User with email "${email}" not found. Note: Only Reftab users (not external loanees) can be assigned to maintenance.`,
  );
}

export class Reftab implements INodeType {
  description: INodeTypeDescription = {
    displayName: "Reftab",
    name: "reftab",
    icon: "file:reftab.svg",
    group: ["transform"],
    version: 1,
    subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
    description: "Interact with Reftab API",
    defaults: {
      name: "Reftab",
    },
    inputs: ["main"],
    outputs: ["main"],
    credentials: [
      {
        name: "reftabApi",
        required: true,
        testedBy: 'reftabApiTest',
      },
    ],
    properties: [
      {
        displayName: "Resource",
        name: "resource",
        type: "options",
        noDataExpression: true,
        options: [
          {
            name: "Asset",
            value: "asset",
          },
          {
            name: "Asset Maintenance",
            value: "assetMaintenance",
          },
          {
            name: "Loan",
            value: "loan",
          },
          {
            name: "Reservation",
            value: "reservation",
          },
          {
            name: "Custom",
            value: "custom",
          },
        ],
        default: "asset",
      },
      // Asset Operations
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["asset"],
          },
        },
        options: [
          {
            name: "Get",
            value: "get",
            description: "Get an asset by ID",
            action: "Get an asset",
          },
          {
            name: "Get Many",
            value: "getAll",
            description: "Get multiple assets",
            action: "Get many assets",
          },
          {
            name: "Create",
            value: "create",
            description: "Create a new asset",
            action: "Create an asset",
          },
          {
            name: "Update",
            value: "update",
            description: "Update an asset",
            action: "Update an asset",
          },
          {
            name: "Delete",
            value: "delete",
            description: "Delete an asset",
            action: "Delete an asset",
          },
        ],
        default: "get",
      },
      // Asset ID (for get, update, delete)
      {
        displayName: "Asset ID",
        name: "assetId",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["get", "update", "delete"],
          },
        },
        default: "",
        description: "The ID of the asset",
      },
      // Get Many options
      {
        displayName: "Limit",
        name: "limit",
        type: "number",
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["getAll"],
          },
        },
        typeOptions: {
          minValue: 1,
        },
        default: 100,
        description: "The number of assets to get (default: 100)",
      },
      {
        displayName: "Additional Parameters",
        name: "additionalParams",
        type: "collection",
        placeholder: "Add Parameter",
        default: {},
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["getAll"],
          },
        },
        options: [
          {
            displayName: "Offset",
            name: "offset",
            type: "number",
            default: 0,
            description: "The number of assets offset (default: 0)",
          },
          {
            displayName: "Location",
            name: "clid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getLocations",
            },
            default: "",
            description: "Location ID to limit by",
          },
          {
            displayName: "Category",
            name: "cid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getCategories",
            },
            default: "",
            description: "Category ID to limit by",
          },
          {
            displayName: "Status",
            name: "status",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getStatuses",
            },
            default: "",
            description: "Status ID to limit by",
          },
          {
            displayName: "Loan Status",
            name: "loan",
            type: "options",
            options: [
              {
                name: "In",
                value: "in",
              },
              {
                name: "Out",
                value: "out",
              },
            ],
            default: "",
            description: "Limit by loan status",
          },
          {
            displayName: "Loanee Email",
            name: "loanee",
            type: "string",
            default: "",
            placeholder: "user@example.com",
            description: "Limit by email of current loanee",
          },
        ],
      },
      {
        displayName: "Field Filters",
        name: "fieldFilters",
        type: "fixedCollection",
        typeOptions: {
          multipleValues: true,
        },
        placeholder: "Add Field Filter",
        default: {},
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["getAll"],
          },
        },
        description: "Filter by a field and its value. Format: {fid}|{value}",
        options: [
          {
            displayName: "Filter",
            name: "filters",
            values: [
              {
                displayName: "Field",
                name: "fid",
                type: "options",
                typeOptions: {
                  loadOptionsMethod: "getFields",
                },
                default: "",
                description: "The field to filter by",
              },
              {
                displayName: "Value",
                name: "value",
                type: "string",
                default: "",
                description: "The value to filter for",
              },
            ],
          },
        ],
      },
      // Create Asset fields
      {
        displayName: "Location",
        name: "location",
        type: "options",
        required: true,
        typeOptions: {
          loadOptionsMethod: "getLocations",
        },
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["create"],
          },
        },
        default: "",
        description: "The location for the asset",
      },
      {
        displayName: "Category",
        name: "category",
        type: "options",
        required: true,
        typeOptions: {
          loadOptionsMethod: "getCategories",
        },
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["create"],
          },
        },
        default: "",
        description: "The category for the asset",
      },
      {
        displayName: "Asset Title",
        name: "assetTitle",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["create"],
          },
        },
        default: "",
        description: "The title/name of the asset",
      },
      {
        displayName: "Asset ID",
        name: "newAssetId",
        type: "string",
        required: false,
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["create"],
          },
        },
        default: "",
        placeholder: "Leave blank to auto-generate",
        description:
          'Optional custom Asset ID. If left blank, Reftab will auto-generate an ID. Use the Custom API Call with GET on "nextasset" endpoint to see the next ID.',
      },
      {
        displayName: "Additional Fields",
        name: "additionalFields",
        type: "json",
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["create"],
          },
        },
        default: "{}",
        description: "Additional asset fields as JSON object (optional)",
      },
      // Asset data (for update only now)
      {
        displayName: "Asset Data",
        name: "assetData",
        type: "json",
        required: true,
        displayOptions: {
          show: {
            resource: ["asset"],
            operation: ["update"],
          },
        },
        default: '{\n  "title": "",\n  "status": ""\n}',
        description:
          "Asset data as JSON object - only include fields you want to update",
      },
      // Asset Maintenance Operations
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
          },
        },
        options: [
          {
            name: "Get",
            value: "get",
            description: "Get a maintenance record by ID",
            action: "Get a maintenance record",
          },
          {
            name: "Get Many",
            value: "getAll",
            description: "Get multiple maintenance records",
            action: "Get many maintenance records",
          },
          {
            name: "Create",
            value: "create",
            description: "Create a new maintenance record for an asset",
            action: "Create a maintenance record",
          },
        ],
        default: "get",
      },
      // Asset Maintenance ID (for get only now)
      {
        displayName: "Maintenance ID",
        name: "maintenanceId",
        type: "number",
        required: true,
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["get"],
          },
        },
        default: 0,
        description: "The ID of the maintenance record (amid)",
      },
      // Get Many Asset Maintenance options
      {
        displayName: "Limit",
        name: "maintenanceLimit",
        type: "number",
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["getAll"],
          },
        },
        typeOptions: {
          minValue: 1,
        },
        default: 100,
        description: "The number of maintenance records to get",
      },
      {
        displayName: "Additional Parameters",
        name: "maintenanceAdditionalParams",
        type: "collection",
        placeholder: "Add Parameter",
        default: {},
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["getAll"],
          },
        },
        options: [
          {
            displayName: "Offset",
            name: "offset",
            type: "number",
            default: 0,
            description: "Pagination offset",
          },
          {
            displayName: "Location",
            name: "clid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getLocations",
            },
            default: "",
            description: "Location ID to filter by",
          },
          {
            displayName: "Asset ID",
            name: "aid",
            type: "string",
            default: "",
            description: "Asset ID to filter by",
          },
          {
            displayName: "Maintenance ID",
            name: "amid",
            type: "number",
            default: 0,
            description: "Single maintenance ID to filter by",
          },
          {
            displayName: "Maintenance Template ID",
            name: "mnid",
            type: "string",
            default: "",
            description: "Maintenance template ID to filter by",
          },
          {
            displayName: "Assigned User ID",
            name: "uid",
            type: "number",
            default: 0,
            description: "User ID to filter by assigned user",
          },
          {
            displayName: "Assigned User Email",
            name: "assignedEmail",
            type: "string",
            default: "",
            placeholder: "user@example.com",
            description:
              "Filter by assigned user email - will look up the user ID automatically",
          },
          {
            displayName: "Completed Status",
            name: "completed",
            type: "options",
            options: [
              {
                name: "All",
                value: "",
              },
              {
                name: "Completed",
                value: "true",
              },
              {
                name: "Pending",
                value: "false",
              },
            ],
            default: "",
            description: "Filter by completion status",
          },
        ],
      },
      // Create Asset Maintenance fields
      {
        displayName: "Asset ID",
        name: "maintenanceAssetId",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["create"],
          },
        },
        default: "",
        description: "The Asset ID to create maintenance for",
      },
      {
        displayName: "Maintenance Template ID",
        name: "maintenanceMnid",
        type: "number",
        required: true,
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["create"],
          },
        },
        default: 0,
        description: "The Maintenance Template ID (mnid)",
      },
      {
        displayName: "Start Date",
        name: "maintenanceStart",
        type: "dateTime",
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["create"],
          },
        },
        default: "",
        description: "Start date of maintenance",
      },
      {
        displayName: "Due Date",
        name: "maintenanceDue",
        type: "dateTime",
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["create"],
          },
        },
        default: "",
        description: "Due date of maintenance",
      },
      {
        displayName: "Additional Create Options",
        name: "maintenanceCreateOptions",
        type: "collection",
        placeholder: "Add Option",
        default: {},
        displayOptions: {
          show: {
            resource: ["assetMaintenance"],
            operation: ["create"],
          },
        },
        options: [
          {
            displayName: "Assigned User ID",
            name: "assignedUid",
            type: "number",
            default: 0,
            description: "User ID of the person assigned to this maintenance",
          },
          {
            displayName: "Assigned User Email",
            name: "assignedEmail",
            type: "string",
            default: "",
            placeholder: "user@example.com",
            description:
              "Email of user to assign - will look up the user ID automatically",
          },
        ],
      },
      // Loan Operations
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["loan"],
          },
        },
        options: [
          {
            name: "Get",
            value: "get",
            description: "Get a loan by ID",
            action: "Get a loan",
          },
          {
            name: "Get Many",
            value: "getAll",
            description: "Get multiple loans",
            action: "Get many loans",
          },
          {
            name: "Create",
            value: "create",
            description: "Create a new loan (check out)",
            action: "Create a loan",
          },
          {
            name: "Update",
            value: "update",
            description: "Update a loan",
            action: "Update a loan",
          },
          {
            name: "Check In",
            value: "checkIn",
            description: "Check in / return a loan",
            action: "Check in a loan",
          },
        ],
        default: "get",
      },
      // Loan ID (for get, update, checkIn)
      {
        displayName: "Loan ID",
        name: "loanId",
        type: "number",
        required: true,
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["get", "update", "checkIn"],
          },
        },
        default: 0,
        description: "The ID of the loan",
      },
      // Get Many Loans options
      {
        displayName: "Limit",
        name: "loanLimit",
        type: "number",
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["getAll"],
          },
        },
        typeOptions: {
          minValue: 1,
        },
        default: 100,
        description: "The number of loans to get (default: 100)",
      },
      {
        displayName: "Additional Parameters",
        name: "loanAdditionalParams",
        type: "collection",
        placeholder: "Add Parameter",
        default: {},
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["getAll"],
          },
        },
        options: [
          {
            displayName: "Offset",
            name: "offset",
            type: "number",
            default: 0,
            description: "The number of loans offset (default: 0)",
          },
          {
            displayName: "Location",
            name: "clid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getLocations",
            },
            default: "",
            description: "Location ID to limit by",
          },
          {
            displayName: "Category",
            name: "cid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getCategories",
            },
            default: "",
            description: "Category ID to limit by",
          },
          {
            displayName: "Asset ID",
            name: "aid",
            type: "string",
            default: "",
            description: "Asset ID to limit by",
          },
          {
            displayName: "License ID",
            name: "licid",
            type: "number",
            default: 0,
            description: "License ID to limit by",
          },
          {
            displayName: "Kit ID",
            name: "kid",
            type: "number",
            default: 0,
            description: "Kit ID to limit by",
          },
          {
            displayName: "Accessory ID",
            name: "accid",
            type: "number",
            default: 0,
            description: "Accessory ID to limit by",
          },
          {
            displayName: "Loan ID",
            name: "lid",
            type: "number",
            default: 0,
            description: "Loan ID to limit by",
          },
          {
            displayName: "User ID",
            name: "loan_uid",
            type: "number",
            default: 0,
            description: "User ID to limit by",
          },
          {
            displayName: "Loanee ID",
            name: "lnid",
            type: "number",
            default: 0,
            description: "Loanee ID to limit by",
          },
          {
            displayName: "Loan Status",
            name: "status",
            type: "options",
            options: [
              {
                name: "In",
                value: "in",
              },
              {
                name: "Out",
                value: "out",
              },
            ],
            default: "",
            description: 'Limit by loan status, "in" or "out"',
          },
          {
            displayName: "Item Type",
            name: "type",
            type: "options",
            options: [
              {
                name: "Asset",
                value: "asset",
              },
              {
                name: "License",
                value: "license",
              },
              {
                name: "Accessory",
                value: "accessory",
              },
              {
                name: "Kit",
                value: "kit",
              },
            ],
            default: "",
            description: "Limit by item type",
          },
          {
            displayName: "Loanee Search",
            name: "loanee",
            type: "string",
            default: "",
            placeholder: "Search by email or name",
            description: "Limit by loanee, string search within email and name",
          },
          {
            displayName: "Loan Group ID",
            name: "lgid",
            type: "number",
            default: 0,
            description: "Loan Group ID to limit by",
          },
          {
            displayName: "Activity Since",
            name: "activitySince",
            type: "dateTime",
            default: "",
            description:
              "Get loans with check in or check out after this datetime (inclusive). ISO8601 format.",
          },
          {
            displayName: "Activity Until",
            name: "activityUntil",
            type: "dateTime",
            default: "",
            description:
              "Get loans with check in or check out before this datetime (not inclusive). ISO8601 format.",
          },
        ],
      },
      // Create Loan fields
      {
        displayName: "Loanee Email",
        name: "loaneeEmail",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["create"],
          },
        },
        default: "",
        placeholder: "user@example.com",
        description:
          "Email of the loanee. The node will look up the loanee/user ID automatically.",
      },
      {
        displayName: "Items to Loan",
        name: "loanItems",
        type: "fixedCollection",
        typeOptions: {
          multipleValues: true,
        },
        placeholder: "Add Item",
        default: {},
        required: true,
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["create"],
          },
        },
        description: "Items to include in the loan",
        options: [
          {
            displayName: "Assets",
            name: "assets",
            values: [
              {
                displayName: "Asset ID",
                name: "aid",
                type: "string",
                default: "",
                description: "The Asset ID to loan",
              },
            ],
          },
          {
            displayName: "Licenses",
            name: "licenses",
            values: [
              {
                displayName: "License ID",
                name: "licid",
                type: "number",
                default: 0,
                description: "The License ID to loan",
              },
            ],
          },
          {
            displayName: "Accessories",
            name: "accessories",
            values: [
              {
                displayName: "Accessory ID",
                name: "accid",
                type: "number",
                default: 0,
                description: "The Accessory ID to loan",
              },
            ],
          },
          {
            displayName: "Kits",
            name: "kits",
            values: [
              {
                displayName: "Kit ID",
                name: "kid",
                type: "number",
                default: 0,
                description: "The Kit ID to loan",
              },
            ],
          },
        ],
      },
      {
        displayName: "Additional Loan Options",
        name: "loanOptions",
        type: "collection",
        placeholder: "Add Option",
        default: {},
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["create"],
          },
        },
        options: [
          {
            displayName: "Due Date",
            name: "due",
            type: "dateTime",
            default: "",
            description:
              "Due date for the loan. Leave empty for indefinite loan.",
          },
          {
            displayName: "Notes",
            name: "notes",
            type: "string",
            default: "",
            description: "Notes for the loan",
          },
          {
            displayName: "Signature",
            name: "signature",
            type: "string",
            default: "",
            description: "Signature data for the loan",
          },
          {
            displayName: "Remote Signature",
            name: "remoteSignature",
            type: "boolean",
            default: false,
            description:
              "Whether to bypass signature requirement for remote/automated checkouts",
          },
          {
            displayName: "Loan Group ID",
            name: "lgid",
            type: "number",
            default: 0,
            description: "Loan Group ID to assign",
          },
        ],
      },
      // Update Loan fields
      {
        displayName: "Update Fields",
        name: "loanUpdateFields",
        type: "collection",
        placeholder: "Add Field",
        default: {},
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["update"],
          },
        },
        options: [
          {
            displayName: "Status",
            name: "status",
            type: "options",
            options: [
              {
                name: "In (Returned)",
                value: "in",
              },
              {
                name: "Out",
                value: "out",
              },
            ],
            default: "out",
            description: 'Loan status - set to "in" to return the loan',
          },
          {
            displayName: "Notes",
            name: "notes",
            type: "string",
            default: "",
            description: "Loan notes",
          },
          {
            displayName: "Due Date",
            name: "due",
            type: "dateTime",
            default: "",
            description:
              "Due date to change to (only if status remains out). Send empty string to loan indefinitely.",
          },
          {
            displayName: "Return Location",
            name: "clid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getLocations",
            },
            default: "",
            description: "Location to move asset to after checking in",
          },
        ],
      },
      // Check In fields
      {
        displayName: "Return Location",
        name: "checkInLocation",
        type: "options",
        typeOptions: {
          loadOptionsMethod: "getLocations",
        },
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["checkIn"],
          },
        },
        default: "",
        description:
          "Location to move the asset to after checking in (optional)",
      },
      {
        displayName: "Check In Notes",
        name: "checkInNotes",
        type: "string",
        displayOptions: {
          show: {
            resource: ["loan"],
            operation: ["checkIn"],
          },
        },
        default: "",
        description: "Notes to add when checking in (optional)",
      },
      // Reservation Operations
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
          },
        },
        options: [
          {
            name: "Get",
            value: "get",
            description: "Get a reservation by ID",
            action: "Get a reservation",
          },
          {
            name: "Get Many",
            value: "getAll",
            description: "Get multiple reservations",
            action: "Get many reservations",
          },
          {
            name: "Create",
            value: "create",
            description: "Create a new reservation",
            action: "Create a reservation",
          },
          {
            name: "Update",
            value: "update",
            description: "Update a reservation",
            action: "Update a reservation",
          },
          {
            name: "Delete",
            value: "delete",
            description: "Delete a reservation",
            action: "Delete a reservation",
          },
          {
            name: "Fulfill",
            value: "fulfill",
            description: "Fulfill a reservation (convert to loan)",
            action: "Fulfill a reservation",
          },
        ],
        default: "get",
      },
      // Reservation ID (for get, update, delete, fulfill)
      {
        displayName: "Reservation ID",
        name: "reservationId",
        type: "number",
        required: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["get", "update", "delete", "fulfill"],
          },
        },
        default: 0,
        description: "The ID of the reservation",
      },
      // Get Many Reservations options
      {
        displayName: "Limit",
        name: "reservationLimit",
        type: "number",
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["getAll"],
          },
        },
        typeOptions: {
          minValue: 1,
        },
        default: 100,
        description: "The number of reservations to get",
      },
      {
        displayName: "Additional Parameters",
        name: "reservationAdditionalParams",
        type: "collection",
        placeholder: "Add Parameter",
        default: {},
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["getAll"],
          },
        },
        options: [
          {
            displayName: "Location",
            name: "clid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getLocations",
            },
            default: "",
            description: "Location ID to limit by",
          },
          {
            displayName: "Category",
            name: "cid",
            type: "options",
            typeOptions: {
              loadOptionsMethod: "getCategories",
            },
            default: "",
            description: "Category ID to limit by",
          },
          {
            displayName: "Asset ID",
            name: "aid",
            type: "string",
            default: "",
            description: "Asset ID to limit by",
          },
          {
            displayName: "License ID",
            name: "licid",
            type: "number",
            default: 0,
            description: "License ID to limit by",
          },
          {
            displayName: "Kit ID",
            name: "kid",
            type: "number",
            default: 0,
            description: "Kit ID to limit by",
          },
          {
            displayName: "Accessory ID",
            name: "accid",
            type: "number",
            default: 0,
            description: "Accessory ID to limit by",
          },
          {
            displayName: "Loan ID",
            name: "lid",
            type: "number",
            default: 0,
            description: "Loan ID to limit by",
          },
          {
            displayName: "User ID",
            name: "loan_uid",
            type: "number",
            default: 0,
            description: "User ID to limit by",
          },
          {
            displayName: "Loanee ID",
            name: "lnid",
            type: "number",
            default: 0,
            description: "Loanee ID to limit by",
          },
          {
            displayName: "Loanee Email",
            name: "loaneeEmail",
            type: "string",
            default: "",
            placeholder: "user@example.com",
            description:
              "Filter by loanee email - will look up the loanee/user ID automatically",
          },
          {
            displayName: "Status",
            name: "status",
            type: "options",
            options: [
              {
                name: "Reserved",
                value: "reserved",
              },
              {
                name: "Cancelled",
                value: "cancelled",
              },
              {
                name: "Fulfilled",
                value: "fulfilled",
              },
            ],
            default: "reserved",
            description: "Limit by reservation status",
          },
          {
            displayName: "Loan Group ID",
            name: "lgid",
            type: "number",
            default: 0,
            description: "Loan Group ID to limit by",
          },
        ],
      },
      // Create Reservation fields
      {
        displayName: "Loanee Email",
        name: "reservationLoaneeEmail",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["create"],
          },
        },
        default: "",
        placeholder: "user@example.com",
        description:
          "Email of the loanee. The node will look up the loanee/user ID automatically.",
      },
      {
        displayName: "Start Date",
        name: "reservationStart",
        type: "dateTime",
        required: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["create"],
          },
        },
        default: "",
        description: "Start date/time of the reservation",
      },
      {
        displayName: "End Date",
        name: "reservationEnd",
        type: "dateTime",
        required: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["create"],
          },
        },
        default: "",
        description: "End date/time of the reservation",
      },
      {
        displayName: "Items to Reserve",
        name: "reservationItems",
        type: "fixedCollection",
        typeOptions: {
          multipleValues: true,
        },
        placeholder: "Add Item",
        default: {},
        required: true,
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["create"],
          },
        },
        description: "Items to include in the reservation",
        options: [
          {
            displayName: "Assets",
            name: "assets",
            values: [
              {
                displayName: "Asset ID",
                name: "aid",
                type: "string",
                default: "",
                description: "The Asset ID to reserve",
              },
            ],
          },
          {
            displayName: "Licenses",
            name: "licenses",
            values: [
              {
                displayName: "License ID",
                name: "licid",
                type: "number",
                default: 0,
                description: "The License ID to reserve",
              },
            ],
          },
          {
            displayName: "Accessories",
            name: "accessories",
            values: [
              {
                displayName: "Accessory ID",
                name: "accid",
                type: "number",
                default: 0,
                description: "The Accessory ID to reserve",
              },
            ],
          },
          {
            displayName: "Kits",
            name: "kits",
            values: [
              {
                displayName: "Kit ID",
                name: "kid",
                type: "number",
                default: 0,
                description: "The Kit ID to reserve",
              },
            ],
          },
        ],
      },
      {
        displayName: "Additional Reservation Options",
        name: "reservationOptions",
        type: "collection",
        placeholder: "Add Option",
        default: {},
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["create"],
          },
        },
        options: [
          {
            displayName: "Notes",
            name: "notes",
            type: "string",
            default: "",
            description: "Notes for the reservation",
          },
          {
            displayName: "Loan Group ID",
            name: "lgid",
            type: "number",
            default: 0,
            description: "Loan Group ID to assign",
          },
        ],
      },
      // Update Reservation fields
      {
        displayName: "Update Fields",
        name: "reservationUpdateFields",
        type: "collection",
        placeholder: "Add Field",
        default: {},
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["update"],
          },
        },
        options: [
          {
            displayName: "Status",
            name: "status",
            type: "options",
            options: [
              {
                name: "Reserved",
                value: "reserved",
              },
              {
                name: "Cancelled",
                value: "cancelled",
              },
            ],
            default: "reserved",
            description: "Reservation status",
          },
          {
            displayName: "Start Date",
            name: "start",
            type: "dateTime",
            default: "",
            description: "Start date/time of the reservation",
          },
          {
            displayName: "End Date",
            name: "end",
            type: "dateTime",
            default: "",
            description: "End date/time of the reservation",
          },
          {
            displayName: "Notes",
            name: "notes",
            type: "string",
            default: "",
            description: "Reservation notes",
          },
        ],
      },
      // Fulfill Reservation options
      {
        displayName: "Fulfill Options",
        name: "fulfillOptions",
        type: "collection",
        placeholder: "Add Option",
        default: {},
        displayOptions: {
          show: {
            resource: ["reservation"],
            operation: ["fulfill"],
          },
        },
        options: [
          {
            displayName: "Remote Signature",
            name: "remoteSignature",
            type: "boolean",
            default: false,
            description:
              "Whether to bypass signature requirement for remote/automated checkouts",
          },
          {
            displayName: "Notes",
            name: "notes",
            type: "string",
            default: "",
            description: "Notes for the loan",
          },
        ],
      },
      // Custom Operation
      {
        displayName: "Operation",
        name: "operation",
        type: "options",
        noDataExpression: true,
        displayOptions: {
          show: {
            resource: ["custom"],
          },
        },
        options: [
          {
            name: "API Call",
            value: "apiCall",
            description: "Make a custom API call",
            action: "Make a custom API call",
          },
        ],
        default: "apiCall",
      },
      {
        displayName: "HTTP Method",
        name: "method",
        type: "options",
        displayOptions: {
          show: {
            resource: ["custom"],
            operation: ["apiCall"],
          },
        },
        options: [
          {
            name: "GET",
            value: "GET",
          },
          {
            name: "POST",
            value: "POST",
          },
          {
            name: "PUT",
            value: "PUT",
          },
          {
            name: "DELETE",
            value: "DELETE",
          },
        ],
        default: "GET",
        description: "The HTTP method to use",
      },
      {
        displayName: "Endpoint",
        name: "endpoint",
        type: "string",
        required: true,
        displayOptions: {
          show: {
            resource: ["custom"],
            operation: ["apiCall"],
          },
        },
        default: "",
        placeholder: "assets",
        description: "The API endpoint (without leading slash)",
      },
      {
        displayName: "Resource ID",
        name: "resourceId",
        type: "string",
        displayOptions: {
          show: {
            resource: ["custom"],
            operation: ["apiCall"],
          },
        },
        default: "",
        description: "Optional resource ID to append to endpoint",
      },
      {
        displayName: "Query Parameters",
        name: "queryParameters",
        type: "string",
        displayOptions: {
          show: {
            resource: ["custom"],
            operation: ["apiCall"],
          },
        },
        default: "",
        placeholder: "limit=100&status=active",
        description: "Query parameters as key=value pairs separated by &",
      },
      {
        displayName: "Body",
        name: "body",
        type: "json",
        displayOptions: {
          show: {
            resource: ["custom"],
            operation: ["apiCall"],
            method: ["POST", "PUT"],
          },
        },
        default: "{}",
        description: "Request body as JSON",
      },
    ],
  };

  methods = {
    credentialTest: {
      async reftabApiTest(
        this: ICredentialTestFunctions,
        credential: ICredentialsDecrypted,
      ): Promise<INodeCredentialTestResult> {
        const credentials = credential.data as IDataObject;
        const publicKey = credentials.publicKey as string;
        const secretKey = credentials.secretKey as string;
  
        if (!publicKey || !secretKey) {
          return {
            status: 'Error',
            message: 'Public Key and Secret Key are required',
          };
        }
  
        try {
          const url = 'https://www.reftab.com/api/locations';
          const method = 'GET';
          const now = new Date().toUTCString();
  
          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac('sha256', secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest('hex');
          const signature = Buffer.from(hexDigest).toString('base64');
  
          const response = await this.helpers.request({
            method: 'GET',
            url,
            headers: {
              'Authorization': `RT ${publicKey}:${signature}`,
              'x-rt-date': now,
            },
            json: true,
          });
  
          if (response) {
            return {
              status: 'OK',
              message: 'Connection successful',
            };
          }
  
          return {
            status: 'Error',
            message: 'Unknown error occurred',
          };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Unknown error';
          return {
            status: 'Error',
            message: `Connection failed: ${errorMessage}`,
          };
        }
      },
    },
    loadOptions: {
      async getLocations(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        try {
          const credentials = await this.getCredentials("reftabApi");
          const publicKey = credentials.publicKey as string;
          const secretKey = credentials.secretKey as string;
          const url = "https://www.reftab.com/api/locations";
          const method = "GET";
          const now = new Date().toUTCString();

          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac("sha256", secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest("hex");
          const signature = Buffer.from(hexDigest).toString("base64");

          const response = await this.helpers.httpRequest({
            method: "GET",
            url,
            headers: {
              Authorization: `RT ${publicKey}:${signature}`,
              "x-rt-date": now,
            },
          });

          // Flatten nested array if present and recursively get all locations including children
          const flattenLocations = (
            items: Record<string, unknown>[],
            prefix = "",
          ): INodePropertyOptions[] => {
            const result: INodePropertyOptions[] = [];
            for (const loc of items) {
              const name = prefix
                ? `${prefix} > ${loc.name}`
                : String(loc.name || "");
              result.push({
                name,
                value: String(loc.clid || ""),
              });
              // Recursively add children
              if (Array.isArray(loc.children) && loc.children.length > 0) {
                result.push(
                  ...flattenLocations(
                    loc.children as Record<string, unknown>[],
                    name,
                  ),
                );
              }
            }
            return result;
          };

          // Handle nested array structure [[...]]
          let locations = response;
          if (
            Array.isArray(response) &&
            response.length > 0 &&
            Array.isArray(response[0])
          ) {
            locations = response[0];
          }

          return flattenLocations(Array.isArray(locations) ? locations : []);
        } catch (_error) {
          return [{ name: "Error loading locations", value: "" }];
        }
      },
      async getCategories(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        try {
          const credentials = await this.getCredentials("reftabApi");
          const publicKey = credentials.publicKey as string;
          const secretKey = credentials.secretKey as string;
          const url = "https://www.reftab.com/api/categories";
          const method = "GET";
          const now = new Date().toUTCString();

          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac("sha256", secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest("hex");
          const signature = Buffer.from(hexDigest).toString("base64");

          const response = await this.helpers.httpRequest({
            method: "GET",
            url,
            headers: {
              Authorization: `RT ${publicKey}:${signature}`,
              "x-rt-date": now,
            },
          });

          // Handle nested array structure [[...]]
          let categories = response;
          if (
            Array.isArray(response) &&
            response.length > 0 &&
            Array.isArray(response[0])
          ) {
            categories = response[0];
          }

          const catArray = Array.isArray(categories) ? categories : [];
          return catArray.map((cat: Record<string, unknown>) => ({
            name: String(cat.name || ""),
            value: String(cat.cid || ""),
          }));
        } catch (_error) {
          return [{ name: "Error loading categories", value: "" }];
        }
      },
      async getNextAssetId(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        try {
          const credentials = await this.getCredentials("reftabApi");
          const publicKey = credentials.publicKey as string;
          const secretKey = credentials.secretKey as string;
          const url = "https://www.reftab.com/api/nextasset";
          const method = "GET";
          const now = new Date().toUTCString();

          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac("sha256", secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest("hex");
          const signature = Buffer.from(hexDigest).toString("base64");

          const response = (await this.helpers.httpRequest({
            method: "GET",
            url,
            headers: {
              Authorization: `RT ${publicKey}:${signature}`,
              "x-rt-date": now,
            },
          })) as Record<string, unknown>;

          const nextId = String(response.aid || response.id || "Unknown");
          return [{ name: `Next generated ID: ${nextId}`, value: "" }];
        } catch (_error) {
          return [{ name: "Could not fetch next ID", value: "" }];
        }
      },
      async getStatuses(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        try {
          const credentials = await this.getCredentials("reftabApi");
          const publicKey = credentials.publicKey as string;
          const secretKey = credentials.secretKey as string;
          const url = "https://www.reftab.com/api/status";
          const method = "GET";
          const now = new Date().toUTCString();

          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac("sha256", secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest("hex");
          const signature = Buffer.from(hexDigest).toString("base64");

          const response = await this.helpers.httpRequest({
            method: "GET",
            url,
            headers: {
              Authorization: `RT ${publicKey}:${signature}`,
              "x-rt-date": now,
            },
          });

          // Handle nested array structure [[...]]
          let statuses = response;
          if (
            Array.isArray(response) &&
            response.length > 0 &&
            Array.isArray(response[0])
          ) {
            statuses = response[0];
          }

          const statusArray = Array.isArray(statuses) ? statuses : [];
          return statusArray.map((status: Record<string, unknown>) => ({
            name: String(status.name || status.title || ""),
            value: String(status.statid || status.id || ""),
          }));
        } catch (_error) {
          return [{ name: "Error loading statuses", value: "" }];
        }
      },
      async getFields(
        this: ILoadOptionsFunctions,
      ): Promise<INodePropertyOptions[]> {
        try {
          const credentials = await this.getCredentials("reftabApi");
          const publicKey = credentials.publicKey as string;
          const secretKey = credentials.secretKey as string;
          const url = "https://www.reftab.com/api/fields";
          const method = "GET";
          const now = new Date().toUTCString();

          const signatureString = `${method}\n\n\n${now}\n${url}`;
          const hmac = crypto.createHmac("sha256", secretKey);
          hmac.update(signatureString);
          const hexDigest = hmac.digest("hex");
          const signature = Buffer.from(hexDigest).toString("base64");

          const response = await this.helpers.httpRequest({
            method: "GET",
            url,
            headers: {
              Authorization: `RT ${publicKey}:${signature}`,
              "x-rt-date": now,
            },
          });

          // Handle nested array structure [[...]]
          let fields = response;
          if (
            Array.isArray(response) &&
            response.length > 0 &&
            Array.isArray(response[0])
          ) {
            fields = response[0];
          }

          const fieldArray = Array.isArray(fields) ? fields : [];
          return fieldArray.map((field: Record<string, unknown>) => ({
            name: String(field.name || ""),
            value: String(field.fid || field.id || ""),
          }));
        } catch (_error) {
          return [{ name: "Error loading fields", value: "" }];
        }
      },
    },
  };

  // The execute method - 'this' is bound to IExecuteFunctions by n8n at runtime
  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];
    const resource = this.getNodeParameter("resource", 0) as string;
    const operation = this.getNodeParameter("operation", 0) as string;

    for (let i = 0; i < items.length; i++) {
      try {
        if (resource === "asset") {
          if (operation === "get") {
            const assetId = this.getNodeParameter("assetId", i) as string;
            const responseData = await makeReftabRequest(
              this,
              "GET",
              `assets/${assetId}`,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "getAll") {
            const limit = this.getNodeParameter("limit", i) as number;
            const additionalParams = this.getNodeParameter(
              "additionalParams",
              i,
            ) as IDataObject;
            const fieldFilters = this.getNodeParameter(
              "fieldFilters",
              i,
            ) as IDataObject;

            // Build query parameters
            const queryParams: string[] = [`limit=${limit}`];

            // Add additional parameters
            if (additionalParams) {
              if (
                additionalParams.offset !== undefined &&
                additionalParams.offset !== ""
              ) {
                queryParams.push(`offset=${additionalParams.offset}`);
              }
              if (
                additionalParams.clid !== undefined &&
                additionalParams.clid !== ""
              ) {
                queryParams.push(`clid=${additionalParams.clid}`);
              }
              if (
                additionalParams.cid !== undefined &&
                additionalParams.cid !== ""
              ) {
                queryParams.push(`cid=${additionalParams.cid}`);
              }
              if (
                additionalParams.status !== undefined &&
                additionalParams.status !== ""
              ) {
                queryParams.push(`status=${additionalParams.status}`);
              }
              if (
                additionalParams.loan !== undefined &&
                additionalParams.loan !== ""
              ) {
                queryParams.push(`loan=${additionalParams.loan}`);
              }
              if (
                additionalParams.loanee !== undefined &&
                additionalParams.loanee !== ""
              ) {
                queryParams.push(
                  `loanee=${encodeURIComponent(String(additionalParams.loanee))}`,
                );
              }
            }

            // Add field filters (query parameter)
            if (fieldFilters && fieldFilters.filters) {
              const filters = fieldFilters.filters as Array<{
                fid: string;
                value: string;
              }>;
              if (filters.length > 0) {
                const queryValues = filters
                  .filter((f) => f.fid && f.value)
                  .map((f) => `${f.fid}|${f.value}`)
                  .join(",");
                if (queryValues) {
                  queryParams.push(`query=${encodeURIComponent(queryValues)}`);
                }
              }
            }

            const endpoint = `assets?${queryParams.join("&")}`;
            const responseData = await makeReftabRequest(this, "GET", endpoint);
            const assets = Array.isArray(responseData)
              ? responseData
              : [responseData];

            for (const asset of assets) {
              returnData.push({ json: asset as IDataObject });
            }
          } else if (operation === "create") {
            const location = this.getNodeParameter("location", i) as string;
            const category = this.getNodeParameter("category", i) as string;
            const assetTitle = this.getNodeParameter("assetTitle", i) as string;
            const newAssetId = this.getNodeParameter("newAssetId", i) as string;
            const additionalFieldsRaw = this.getNodeParameter(
              "additionalFields",
              i,
            );
            const additionalFieldsString =
              typeof additionalFieldsRaw === "string"
                ? additionalFieldsRaw
                : JSON.stringify(additionalFieldsRaw);

            let additionalFields: IDataObject = {};
            try {
              additionalFields = JSON.parse(
                additionalFieldsString,
              ) as IDataObject;
            } catch {
              throw new NodeOperationError(
                this.getNode(),
                "Invalid JSON in Additional Fields",
                { itemIndex: i },
              );
            }

            const body: IDataObject = {
              clid: parseInt(location, 10),
              cid: parseInt(category, 10),
              title: assetTitle,
              ...additionalFields,
            };

            // Add asset ID if provided
            if (newAssetId) {
              body.aid = newAssetId;
            }

            const responseData = await makeReftabRequest(
              this,
              "POST",
              "assets",
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "update") {
            const assetId = this.getNodeParameter("assetId", i) as string;
            const assetDataString = this.getNodeParameter(
              "assetData",
              i,
            ) as string;
            let updates: IDataObject;
            try {
              updates = JSON.parse(assetDataString) as IDataObject;
            } catch {
              throw new NodeOperationError(
                this.getNode(),
                "Invalid JSON in Asset Data field",
                { itemIndex: i },
              );
            }
            // Use GET-merge-PUT pattern
            const responseData = await makeReftabPutRequest(
              this,
              `assets/${assetId}`,
              updates,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "delete") {
            const assetId = this.getNodeParameter("assetId", i) as string;
            const responseData = await makeReftabRequest(
              this,
              "DELETE",
              `assets/${assetId}`,
            );
            returnData.push({
              json: {
                success: true,
                id: assetId,
                ...(responseData as IDataObject),
              },
            });
          }
        } else if (resource === "assetMaintenance") {
          if (operation === "get") {
            const maintenanceId = this.getNodeParameter(
              "maintenanceId",
              i,
            ) as number;
            const responseData = await makeReftabRequest(
              this,
              "GET",
              `assetmaintenance/${maintenanceId}`,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "getAll") {
            const limit = this.getNodeParameter(
              "maintenanceLimit",
              i,
            ) as number;
            const additionalParams = this.getNodeParameter(
              "maintenanceAdditionalParams",
              i,
            ) as IDataObject;

            // Build query parameters
            const queryParams: string[] = [`limit=${limit}`];

            if (additionalParams) {
              if (
                additionalParams.offset !== undefined &&
                additionalParams.offset !== "" &&
                additionalParams.offset !== 0
              ) {
                queryParams.push(`offset=${additionalParams.offset}`);
              }
              if (
                additionalParams.clid !== undefined &&
                additionalParams.clid !== ""
              ) {
                queryParams.push(`clid=${additionalParams.clid}`);
              }
              if (
                additionalParams.aid !== undefined &&
                additionalParams.aid !== ""
              ) {
                queryParams.push(
                  `aid=${encodeURIComponent(String(additionalParams.aid))}`,
                );
              }
              if (
                additionalParams.amid !== undefined &&
                additionalParams.amid !== "" &&
                additionalParams.amid !== 0
              ) {
                queryParams.push(`amid=${additionalParams.amid}`);
              }
              if (
                additionalParams.mnid !== undefined &&
                additionalParams.mnid !== ""
              ) {
                queryParams.push(
                  `mnid=${encodeURIComponent(String(additionalParams.mnid))}`,
                );
              }
              if (
                additionalParams.uid !== undefined &&
                additionalParams.uid !== "" &&
                additionalParams.uid !== 0
              ) {
                queryParams.push(`uid=${additionalParams.uid}`);
              }
              // Handle assigned user email lookup
              if (
                additionalParams.assignedEmail !== undefined &&
                additionalParams.assignedEmail !== ""
              ) {
                const userId = await lookupUserByEmail(
                  this,
                  String(additionalParams.assignedEmail),
                );
                queryParams.push(`uid=${userId}`);
              }
              if (
                additionalParams.completed !== undefined &&
                additionalParams.completed !== ""
              ) {
                queryParams.push(`completed=${additionalParams.completed}`);
              }
            }

            const endpoint = `assetmaintenance?${queryParams.join("&")}`;
            const responseData = await makeReftabRequest(this, "GET", endpoint);

            // Handle nested array structure
            let maintenances = responseData;
            if (
              Array.isArray(responseData) &&
              responseData.length > 0 &&
              Array.isArray(responseData[0])
            ) {
              maintenances = responseData[0];
            }
            const maintenanceArray = Array.isArray(maintenances)
              ? maintenances
              : [maintenances];

            for (const maintenance of maintenanceArray) {
              returnData.push({ json: maintenance as IDataObject });
            }
          } else if (operation === "create") {
            const assetId = this.getNodeParameter(
              "maintenanceAssetId",
              i,
            ) as string;
            const mnid = this.getNodeParameter("maintenanceMnid", i) as number;
            const startDate = this.getNodeParameter(
              "maintenanceStart",
              i,
            ) as string;
            const dueDate = this.getNodeParameter(
              "maintenanceDue",
              i,
            ) as string;
            const createOptions = this.getNodeParameter(
              "maintenanceCreateOptions",
              i,
            ) as IDataObject;

            const body: IDataObject = {
              aid: assetId,
              mnid: mnid,
            };

            if (startDate) {
              body.start = startDate;
            }
            if (dueDate) {
              body.due = dueDate;
            }

            // Handle assigned user - email takes precedence
            if (createOptions) {
              if (
                createOptions.assignedEmail !== undefined &&
                createOptions.assignedEmail !== ""
              ) {
                const userId = await lookupUserByEmail(
                  this,
                  String(createOptions.assignedEmail),
                );
                body.assignedUid = userId;
              } else if (
                createOptions.assignedUid !== undefined &&
                createOptions.assignedUid !== "" &&
                createOptions.assignedUid !== 0
              ) {
                body.assignedUid = createOptions.assignedUid;
              }
            }

            const responseData = await makeReftabRequest(
              this,
              "POST",
              `assets/${assetId}/maintenance`,
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          }
        } else if (resource === "loan") {
          if (operation === "get") {
            const loanId = this.getNodeParameter("loanId", i) as number;
            const responseData = await makeReftabRequest(
              this,
              "GET",
              `loans/${loanId}`,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "getAll") {
            const limit = this.getNodeParameter("loanLimit", i) as number;
            const additionalParams = this.getNodeParameter(
              "loanAdditionalParams",
              i,
            ) as IDataObject;

            // Build query parameters
            const queryParams: string[] = [`limit=${limit}`];

            if (additionalParams) {
              if (
                additionalParams.offset !== undefined &&
                additionalParams.offset !== "" &&
                additionalParams.offset !== 0
              ) {
                queryParams.push(`offset=${additionalParams.offset}`);
              }
              if (
                additionalParams.clid !== undefined &&
                additionalParams.clid !== ""
              ) {
                queryParams.push(`clid=${additionalParams.clid}`);
              }
              if (
                additionalParams.cid !== undefined &&
                additionalParams.cid !== ""
              ) {
                queryParams.push(`cid=${additionalParams.cid}`);
              }
              if (
                additionalParams.aid !== undefined &&
                additionalParams.aid !== ""
              ) {
                queryParams.push(
                  `aid=${encodeURIComponent(String(additionalParams.aid))}`,
                );
              }
              if (
                additionalParams.licid !== undefined &&
                additionalParams.licid !== "" &&
                additionalParams.licid !== 0
              ) {
                queryParams.push(`licid=${additionalParams.licid}`);
              }
              if (
                additionalParams.kid !== undefined &&
                additionalParams.kid !== "" &&
                additionalParams.kid !== 0
              ) {
                queryParams.push(`kid=${additionalParams.kid}`);
              }
              if (
                additionalParams.accid !== undefined &&
                additionalParams.accid !== "" &&
                additionalParams.accid !== 0
              ) {
                queryParams.push(`accid=${additionalParams.accid}`);
              }
              if (
                additionalParams.lid !== undefined &&
                additionalParams.lid !== "" &&
                additionalParams.lid !== 0
              ) {
                queryParams.push(`lid=${additionalParams.lid}`);
              }
              if (
                additionalParams.loan_uid !== undefined &&
                additionalParams.loan_uid !== "" &&
                additionalParams.loan_uid !== 0
              ) {
                queryParams.push(`loan_uid=${additionalParams.loan_uid}`);
              }
              if (
                additionalParams.lnid !== undefined &&
                additionalParams.lnid !== "" &&
                additionalParams.lnid !== 0
              ) {
                queryParams.push(`lnid=${additionalParams.lnid}`);
              }
              if (
                additionalParams.status !== undefined &&
                additionalParams.status !== ""
              ) {
                queryParams.push(`status=${additionalParams.status}`);
              }
              if (
                additionalParams.type !== undefined &&
                additionalParams.type !== ""
              ) {
                queryParams.push(`type=${additionalParams.type}`);
              }
              if (
                additionalParams.loanee !== undefined &&
                additionalParams.loanee !== ""
              ) {
                queryParams.push(
                  `loanee=${encodeURIComponent(String(additionalParams.loanee))}`,
                );
              }
              if (
                additionalParams.lgid !== undefined &&
                additionalParams.lgid !== "" &&
                additionalParams.lgid !== 0
              ) {
                queryParams.push(`lgid=${additionalParams.lgid}`);
              }
              if (
                additionalParams.activitySince !== undefined &&
                additionalParams.activitySince !== ""
              ) {
                queryParams.push(
                  `activitySince=${encodeURIComponent(String(additionalParams.activitySince))}`,
                );
              }
              if (
                additionalParams.activityUntil !== undefined &&
                additionalParams.activityUntil !== ""
              ) {
                queryParams.push(
                  `activityUntil=${encodeURIComponent(String(additionalParams.activityUntil))}`,
                );
              }
            }

            const endpoint = `loans?${queryParams.join("&")}`;
            const responseData = await makeReftabRequest(this, "GET", endpoint);

            // Handle nested array structure
            let loans = responseData;
            if (
              Array.isArray(responseData) &&
              responseData.length > 0 &&
              Array.isArray(responseData[0])
            ) {
              loans = responseData[0];
            }
            const loanArray = Array.isArray(loans) ? loans : [loans];

            for (const loan of loanArray) {
              returnData.push({ json: loan as IDataObject });
            }
          } else if (operation === "create") {
            const loaneeEmail = this.getNodeParameter(
              "loaneeEmail",
              i,
            ) as string;
            const loanItems = this.getNodeParameter(
              "loanItems",
              i,
            ) as IDataObject;
            const loanOptions = this.getNodeParameter(
              "loanOptions",
              i,
            ) as IDataObject;

            // Look up loanee by email
            const loaneeInfo = await lookupLoaneeByEmail(this, loaneeEmail);

            // Build the loan body
            const body: IDataObject = {
              ...loaneeInfo,
            };

            // Add items to loan
            if (loanItems.assets) {
              const assets = loanItems.assets as Array<{ aid: string }>;
              body.aids = assets.map((a) => a.aid).filter((a) => a);
            }
            if (loanItems.licenses) {
              const licenses = loanItems.licenses as Array<{ licid: number }>;
              body.licids = licenses.map((l) => l.licid).filter((l) => l);
            }
            if (loanItems.accessories) {
              const accessories = loanItems.accessories as Array<{
                accid: number;
              }>;
              body.accids = accessories.map((a) => a.accid).filter((a) => a);
            }
            if (loanItems.kits) {
              const kits = loanItems.kits as Array<{ kid: number }>;
              body.kids = kits.map((k) => k.kid).filter((k) => k);
            }

            // Add optional fields
            if (loanOptions) {
              if (loanOptions.due) {
                body.due = loanOptions.due;
              }
              if (loanOptions.notes) {
                body.notes = loanOptions.notes;
              }
              if (loanOptions.signature) {
                body.signature = loanOptions.signature;
              }
              if (loanOptions.remoteSignature === true) {
                body.remoteSignature = true;
              }
              if (loanOptions.lgid && loanOptions.lgid !== 0) {
                body.lgid = loanOptions.lgid;
              }
            }

            const responseData = await makeReftabRequest(
              this,
              "POST",
              "loans",
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "update") {
            const loanId = this.getNodeParameter("loanId", i) as number;
            const updateFields = this.getNodeParameter(
              "loanUpdateFields",
              i,
            ) as IDataObject;

            const body: IDataObject = {};

            if (updateFields.status !== undefined) {
              body.status = updateFields.status;
            }
            if (updateFields.notes !== undefined) {
              body.notes = updateFields.notes;
            }
            if (updateFields.due !== undefined) {
              body.due = updateFields.due;
            }
            if (updateFields.clid !== undefined && updateFields.clid !== "") {
              body.clid = parseInt(String(updateFields.clid), 10);
            }

            const responseData = await makeReftabRequest(
              this,
              "PUT",
              `loans/${loanId}`,
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "checkIn") {
            const loanId = this.getNodeParameter("loanId", i) as number;
            const checkInLocation = this.getNodeParameter(
              "checkInLocation",
              i,
            ) as string;
            const checkInNotes = this.getNodeParameter(
              "checkInNotes",
              i,
            ) as string;

            const body: IDataObject = {
              status: "in",
            };

            if (checkInLocation) {
              body.clid = parseInt(checkInLocation, 10);
            }
            if (checkInNotes) {
              body.notes = checkInNotes;
            }

            const responseData = await makeReftabRequest(
              this,
              "PUT",
              `loans/${loanId}`,
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          }
        } else if (resource === "reservation") {
          if (operation === "get") {
            const reservationId = this.getNodeParameter(
              "reservationId",
              i,
            ) as number;
            const responseData = await makeReftabRequest(
              this,
              "GET",
              `reservations/${reservationId}`,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "getAll") {
            const limit = this.getNodeParameter(
              "reservationLimit",
              i,
            ) as number;
            const additionalParams = this.getNodeParameter(
              "reservationAdditionalParams",
              i,
            ) as IDataObject;

            // Build query parameters
            const queryParams: string[] = [`limit=${limit}`];

            if (additionalParams) {
              if (
                additionalParams.clid !== undefined &&
                additionalParams.clid !== ""
              ) {
                queryParams.push(`clid=${additionalParams.clid}`);
              }
              if (
                additionalParams.cid !== undefined &&
                additionalParams.cid !== ""
              ) {
                queryParams.push(`cid=${additionalParams.cid}`);
              }
              if (
                additionalParams.aid !== undefined &&
                additionalParams.aid !== ""
              ) {
                queryParams.push(
                  `aid=${encodeURIComponent(String(additionalParams.aid))}`,
                );
              }
              if (
                additionalParams.licid !== undefined &&
                additionalParams.licid !== "" &&
                additionalParams.licid !== 0
              ) {
                queryParams.push(`licid=${additionalParams.licid}`);
              }
              if (
                additionalParams.kid !== undefined &&
                additionalParams.kid !== "" &&
                additionalParams.kid !== 0
              ) {
                queryParams.push(`kid=${additionalParams.kid}`);
              }
              if (
                additionalParams.accid !== undefined &&
                additionalParams.accid !== "" &&
                additionalParams.accid !== 0
              ) {
                queryParams.push(`accid=${additionalParams.accid}`);
              }
              if (
                additionalParams.lid !== undefined &&
                additionalParams.lid !== "" &&
                additionalParams.lid !== 0
              ) {
                queryParams.push(`lid=${additionalParams.lid}`);
              }
              if (
                additionalParams.loan_uid !== undefined &&
                additionalParams.loan_uid !== "" &&
                additionalParams.loan_uid !== 0
              ) {
                queryParams.push(`loan_uid=${additionalParams.loan_uid}`);
              }
              if (
                additionalParams.lnid !== undefined &&
                additionalParams.lnid !== "" &&
                additionalParams.lnid !== 0
              ) {
                queryParams.push(`lnid=${additionalParams.lnid}`);
              }
              // Handle loanee email lookup
              if (
                additionalParams.loaneeEmail !== undefined &&
                additionalParams.loaneeEmail !== ""
              ) {
                const loaneeInfo = await lookupLoaneeByEmail(
                  this,
                  String(additionalParams.loaneeEmail),
                );
                if (loaneeInfo.lnid) {
                  queryParams.push(`lnid=${loaneeInfo.lnid}`);
                } else if (loaneeInfo.loan_uid) {
                  queryParams.push(`loan_uid=${loaneeInfo.loan_uid}`);
                }
              }
              if (
                additionalParams.status !== undefined &&
                additionalParams.status !== ""
              ) {
                queryParams.push(`status=${additionalParams.status}`);
              }
              if (
                additionalParams.lgid !== undefined &&
                additionalParams.lgid !== "" &&
                additionalParams.lgid !== 0
              ) {
                queryParams.push(`lgid=${additionalParams.lgid}`);
              }
            }

            const endpoint = `reservations?${queryParams.join("&")}`;
            const responseData = await makeReftabRequest(this, "GET", endpoint);

            // Handle nested array structure
            let reservations = responseData;
            if (
              Array.isArray(responseData) &&
              responseData.length > 0 &&
              Array.isArray(responseData[0])
            ) {
              reservations = responseData[0];
            }
            const reservationArray = Array.isArray(reservations)
              ? reservations
              : [reservations];

            for (const reservation of reservationArray) {
              returnData.push({ json: reservation as IDataObject });
            }
          } else if (operation === "create") {
            const loaneeEmail = this.getNodeParameter(
              "reservationLoaneeEmail",
              i,
            ) as string;
            const startDate = this.getNodeParameter(
              "reservationStart",
              i,
            ) as string;
            const endDate = this.getNodeParameter(
              "reservationEnd",
              i,
            ) as string;
            const reservationItems = this.getNodeParameter(
              "reservationItems",
              i,
            ) as IDataObject;
            const reservationOptions = this.getNodeParameter(
              "reservationOptions",
              i,
            ) as IDataObject;

            // Look up loanee by email
            const loaneeInfo = await lookupLoaneeByEmail(this, loaneeEmail);

            // Build the reservation body
            const body: IDataObject = {
              ...loaneeInfo,
              start: startDate,
              end: endDate,
            };

            // Add items to reserve
            if (reservationItems.assets) {
              const assets = reservationItems.assets as Array<{ aid: string }>;
              body.aids = assets.map((a) => a.aid).filter((a) => a);
            }
            if (reservationItems.licenses) {
              const licenses = reservationItems.licenses as Array<{
                licid: number;
              }>;
              body.licids = licenses.map((l) => l.licid).filter((l) => l);
            }
            if (reservationItems.accessories) {
              const accessories = reservationItems.accessories as Array<{
                accid: number;
              }>;
              body.accids = accessories.map((a) => a.accid).filter((a) => a);
            }
            if (reservationItems.kits) {
              const kits = reservationItems.kits as Array<{ kid: number }>;
              body.kids = kits.map((k) => k.kid).filter((k) => k);
            }

            // Add optional fields
            if (reservationOptions) {
              if (reservationOptions.notes) {
                body.notes = reservationOptions.notes;
              }
              if (reservationOptions.lgid && reservationOptions.lgid !== 0) {
                body.lgid = reservationOptions.lgid;
              }
            }

            const responseData = await makeReftabRequest(
              this,
              "POST",
              "reservations",
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "update") {
            const reservationId = this.getNodeParameter(
              "reservationId",
              i,
            ) as number;
            const updateFields = this.getNodeParameter(
              "reservationUpdateFields",
              i,
            ) as IDataObject;

            const body: IDataObject = {};

            if (updateFields.status !== undefined) {
              body.status = updateFields.status;
            }
            if (updateFields.start !== undefined) {
              body.start = updateFields.start;
            }
            if (updateFields.end !== undefined) {
              body.end = updateFields.end;
            }
            if (updateFields.notes !== undefined) {
              body.notes = updateFields.notes;
            }

            const responseData = await makeReftabRequest(
              this,
              "PUT",
              `reservations/${reservationId}`,
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "delete") {
            const reservationId = this.getNodeParameter(
              "reservationId",
              i,
            ) as number;
            const responseData = await makeReftabRequest(
              this,
              "DELETE",
              `reservations/${reservationId}`,
            );
            returnData.push({ json: responseData as IDataObject });
          } else if (operation === "fulfill") {
            const reservationId = this.getNodeParameter(
              "reservationId",
              i,
            ) as number;
            const fulfillOptions = this.getNodeParameter(
              "fulfillOptions",
              i,
            ) as IDataObject;

            const body: IDataObject = {
              status: "fulfilled",
            };

            if (fulfillOptions) {
              if (fulfillOptions.remoteSignature === true) {
                body.remoteSignature = true;
              }
              if (fulfillOptions.notes) {
                body.notes = fulfillOptions.notes;
              }
            }

            const responseData = await makeReftabRequest(
              this,
              "PUT",
              `reservations/${reservationId}`,
              body,
            );
            returnData.push({ json: responseData as IDataObject });
          }
        } else if (resource === "custom") {
          const method = this.getNodeParameter("method", i) as string;
          const endpoint = this.getNodeParameter("endpoint", i) as string;
          const resourceId = this.getNodeParameter("resourceId", i) as string;
          const queryParams = this.getNodeParameter(
            "queryParameters",
            i,
          ) as string;

          let fullEndpoint = endpoint;
          if (resourceId) {
            fullEndpoint += `/${resourceId}`;
          }
          if (queryParams) {
            fullEndpoint += `?${queryParams}`;
          }

          let body: IDataObject | undefined;
          if (method === "POST" || method === "PUT") {
            const bodyDataString = this.getNodeParameter("body", i) as string;
            try {
              body = JSON.parse(bodyDataString) as IDataObject;
            } catch {
              throw new NodeOperationError(
                this.getNode(),
                "Invalid JSON in Body field",
                { itemIndex: i },
              );
            }
          }

          let responseData: IDataObject | IDataObject[];
          if (method === "PUT" && body) {
            // Use GET-merge-PUT pattern for PUT requests
            responseData = await makeReftabPutRequest(this, fullEndpoint, body);
          } else {
            responseData = await makeReftabRequest(
              this,
              method,
              fullEndpoint,
              body,
            );
          }
          returnData.push({ json: responseData as IDataObject });
        }
      } catch (error: unknown) {
        if (this.continueOnFail()) {
          const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
          returnData.push({
            json: { error: errorMessage },
            pairedItem: { item: i },
          });
          continue;
        }
        if (error instanceof NodeOperationError) {
          throw error;
        }
        throw new NodeOperationError(
          this.getNode(),
          error instanceof Error ? error : new Error("Unknown error occurred"),
          { itemIndex: i },
        );
      }
    }

    return [returnData];
  }
}
