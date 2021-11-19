declare const _default: {
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
};
export default _default;
