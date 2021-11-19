declare const _default: {
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
};
export default _default;
