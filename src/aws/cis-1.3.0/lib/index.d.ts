declare const _default: {
    provider: string;
    rules: ({
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            path: string;
            isEmpty: boolean;
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            or: ({
                value: {
                    daysAgo: {};
                    path: string;
                };
                greaterThan: number;
                path?: undefined;
                array_any?: undefined;
            } | {
                path: string;
                array_any: {
                    value: {
                        daysAgo: {};
                        path: string;
                    };
                    greaterThan: number;
                };
                value?: undefined;
                greaterThan?: undefined;
            })[];
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            path: string;
            array_any: {
                and: ({
                    value: {
                        daysAgo: {};
                        path: string;
                    };
                    greaterThan: number;
                    path?: undefined;
                    equal?: undefined;
                } | {
                    path: string;
                    equal: string;
                    value?: undefined;
                    greaterThan?: undefined;
                })[];
            };
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            path: string;
            equal: boolean;
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            path: string;
            lessThan: number;
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            path: string;
            greaterThan: number;
        };
    } | {
        id: string;
        description: string;
        gql: string;
        resource: string;
        conditions: {
            and: {
                path: string;
                isEmpty: boolean;
            }[];
        };
    })[];
};
export default _default;
