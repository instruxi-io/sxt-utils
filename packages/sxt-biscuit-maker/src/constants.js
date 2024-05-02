export const SQLCommandType = {
    DDL: "ddl",
    DML: "dml",
    DQL: "dql",
};

export const SQLOperation = {
    CREATE: "ddl_create",
    ALTER: "ddl_alter",
    DROP: "ddl_drop",
    INSERT: "dml_insert",
    UPDATE: "dml_update",
    MERGE: "dml_merge",
    DELETE: "dml_delete",
    SELECT: "dql_select",
};

Object.freeze(SQLCommandType);
Object.freeze(SQLOperation);