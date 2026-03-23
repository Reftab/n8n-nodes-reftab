import { IExecuteFunctions, INodeExecutionData, INodeType, INodeTypeDescription, ILoadOptionsFunctions, INodePropertyOptions } from 'n8n-workflow';
export declare class Reftab implements INodeType {
    description: INodeTypeDescription;
    methods: {
        loadOptions: {
            getLocations(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]>;
            getCategories(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]>;
            getNextAssetId(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]>;
            getStatuses(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]>;
            getFields(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]>;
        };
    };
    execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]>;
}
