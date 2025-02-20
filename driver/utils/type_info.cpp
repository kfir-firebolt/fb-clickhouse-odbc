#include "driver/utils/type_info.h"
#include "driver/driver.h"
#include <algorithm>

#include <Poco/String.h>

#include <stdexcept>
// #include <sys/syslog.h>

// sql_type_name is the name of the type as returned by the SQL_DESC_TYPE_NAME field of ODBC.
const std::map<std::string, TypeInfo> types_g = {
    // TODO check what is the correct size for each type
    {"bool", TypeInfo {"bool", true, SQL_BIT, 3, 1}},
    {"int", TypeInfo {"int", false, SQL_INTEGER, 1 + 10, 4}},
    {"bigint", TypeInfo {"bigint", false, SQL_BIGINT, 1 + 19, 8}},
    {"real", TypeInfo {"real", false, SQL_REAL, 7, 4}},
    // TODO PG returns SQL_FLOAT for double.
    {"double precision", TypeInfo {"double precision", false, SQL_FLOAT, 15, 8}},
    {"numeric", TypeInfo {"numeric", false, SQL_NUMERIC, 1 + 2 + 38, 16}}, // -0.
    {"text", TypeInfo {"text", true, SQL_LONGVARCHAR, TypeInfo::string_max_size, TypeInfo::string_max_size}},
    {"date", TypeInfo {"DATE", true, SQL_TYPE_DATE, 10, 6}},
    {"timestamp", TypeInfo {"TIMESTAMP", true, SQL_TYPE_TIMESTAMP, 19, 16}},
    {"timestampntz", TypeInfo {"TIMESTAMP", true, SQL_TYPE_TIMESTAMP, 19, 16}},
    {"timestamptz", TypeInfo {"TIMESTAMPTZ", true, SQL_TYPE_TIMESTAMP, 29, 16}},
    {"array", TypeInfo {"array", true, SQL_VARCHAR, TypeInfo::string_max_size, TypeInfo::string_max_size}},
    {"Nothing", TypeInfo {"null", true, SQL_TYPE_NULL, 1, 1}},
    {"bytea", TypeInfo {"bytea", true, SQL_LONGVARBINARY, TypeInfo::string_max_size, TypeInfo::string_max_size}},
};


DataSourceTypeId convertUnparametrizedTypeNameToTypeId(const std::string & type) {
    LOG("Converting type: " + type);
    
    // Convert to lowercase and remove " null" suffix if present
    std::string base_type = type;
    std::transform(base_type.begin(), base_type.end(), base_type.begin(), ::tolower);
    
    size_t null_pos = base_type.find(" null");
    if (null_pos != std::string::npos) {
        base_type = base_type.substr(0, null_pos);
        LOG("Found null suffix, base type: " + base_type);
    }

    // Integer types
    if (base_type == "int" || 
        base_type == "integer" || 
        base_type == "int32" || 
        base_type == "int4")           return DataSourceTypeId::Int32;
        
    if (base_type == "bigint" || 
        base_type == "int64" || 
        base_type == "int8" || 
        base_type == "long")           return DataSourceTypeId::Int64;
        
    if (base_type == "smallint" || 
        base_type == "int16" || 
        base_type == "int2")           return DataSourceTypeId::Int16;
        
    if (base_type == "tinyint" || 
        base_type == "int1")           return DataSourceTypeId::Int8;

    // Floating point types
    if (base_type == "double" || 
        base_type == "float64" || 
        base_type == "double precision") return DataSourceTypeId::Float64;
        
    if (base_type == "float" || 
        base_type == "real" || 
        base_type == "float32")        return DataSourceTypeId::Float32;

    // Date/Time types
    if (base_type == "timestamp" || 
        base_type == "datetime")       return DataSourceTypeId::Timestamp;
        
    if (base_type == "timestamptz" || 
        base_type == "datetime64")     return DataSourceTypeId::TimestampTz;
        
    if (base_type == "date")          return DataSourceTypeId::Date;

    // String types
    if (base_type == "text" || 
        base_type == "string" || 
        base_type == "varchar" || 
        base_type == "char" || 
        base_type == "character varying" || 
        base_type == "character")      return DataSourceTypeId::String;

    // Boolean types
    if (base_type == "boolean" || 
        base_type == "bool")          return DataSourceTypeId::Boolean;

    // Binary types
    if (base_type == "bytea" || 
        base_type == "binary" || 
        base_type == "varbinary")     return DataSourceTypeId::Bytea;

    // Decimal types
    if (base_type == "decimal" || 
        base_type == "numeric")       return DataSourceTypeId::Decimal;
    if (base_type == "decimal32")     return DataSourceTypeId::Decimal32;
    if (base_type == "decimal64")     return DataSourceTypeId::Decimal64;
    if (base_type == "decimal128")    return DataSourceTypeId::Decimal128;

    // Special types
    if (base_type == "nothing" || 
        base_type == "null")          return DataSourceTypeId::Nothing;
    
    // Array types (treat as string for now)
    if (base_type == "array")         return DataSourceTypeId::String;
    
    LOG("Unknown type: " + type + ", returning Unknown");
    return DataSourceTypeId::Unknown;
}

std::string convertTypeIdToUnparametrizedCanonicalTypeName(DataSourceTypeId type_id) {
    switch (type_id) {
        case DataSourceTypeId::Date:        return "Date";
        case DataSourceTypeId::Timestamp:    return "Timestamp";
        case DataSourceTypeId::TimestampTz:  return "TimestampTz";
        case DataSourceTypeId::Decimal:     return "numeric";
        case DataSourceTypeId::Float32:     return "real";
        case DataSourceTypeId::Float64:     return "double precision";
        case DataSourceTypeId::Int32:       return "int";
        case DataSourceTypeId::Int64:       return "bigint";
        case DataSourceTypeId::Nothing:     return "Nothing";
        case DataSourceTypeId::String:      return "text";
        case DataSourceTypeId::Boolean:     return "bool";
        case DataSourceTypeId::Bytea:       return "bytea";

        default:
            throw std::runtime_error("unknown type id:");
    }
}

SQLSMALLINT convertSQLTypeToCType(SQLSMALLINT sql_type) noexcept {
    switch (sql_type) {
        case SQL_TYPE_NULL:
        case SQL_CHAR:
        case SQL_VARCHAR:
        case SQL_LONGVARCHAR:
            return SQL_C_CHAR;

        case SQL_WCHAR:
        case SQL_WVARCHAR:
        case SQL_WLONGVARCHAR:
            return SQL_C_WCHAR;

        case SQL_DECIMAL:
            return SQL_C_CHAR;

        case SQL_NUMERIC:
            return SQL_C_NUMERIC;

        case SQL_BIT:                      return SQL_C_BIT;
        case SQL_TINYINT:                  return SQL_C_TINYINT;
        case SQL_SMALLINT:                 return SQL_C_SHORT;
        case SQL_INTEGER:                  return SQL_C_LONG;
        case SQL_BIGINT:                   return SQL_C_SBIGINT;
        case SQL_REAL:                     return SQL_C_FLOAT;

        case SQL_FLOAT:
        case SQL_DOUBLE:
            return SQL_C_DOUBLE;

        case SQL_BINARY:
        case SQL_VARBINARY:
        case SQL_LONGVARBINARY:
            return SQL_C_BINARY;

        case SQL_TYPE_DATE:                 return SQL_C_TYPE_DATE;
        case SQL_TYPE_TIME:                 return SQL_C_TYPE_TIME;
        case SQL_TYPE_TIMESTAMP:            return SQL_C_TYPE_TIMESTAMP;
        case SQL_INTERVAL_MONTH:            return SQL_C_INTERVAL_MONTH;
        case SQL_INTERVAL_YEAR:             return SQL_C_INTERVAL_YEAR;
        case SQL_INTERVAL_YEAR_TO_MONTH:    return SQL_C_INTERVAL_YEAR_TO_MONTH;
        case SQL_INTERVAL_DAY:              return SQL_C_INTERVAL_DAY;
        case SQL_INTERVAL_HOUR:             return SQL_C_INTERVAL_HOUR;
        case SQL_INTERVAL_MINUTE:           return SQL_C_INTERVAL_MINUTE;
        case SQL_INTERVAL_SECOND:           return SQL_C_INTERVAL_SECOND;
        case SQL_INTERVAL_DAY_TO_HOUR:      return SQL_C_INTERVAL_DAY_TO_HOUR;
        case SQL_INTERVAL_DAY_TO_MINUTE:    return SQL_C_INTERVAL_DAY_TO_MINUTE;
        case SQL_INTERVAL_DAY_TO_SECOND:    return SQL_C_INTERVAL_DAY_TO_SECOND;
        case SQL_INTERVAL_HOUR_TO_MINUTE:   return SQL_C_INTERVAL_HOUR_TO_MINUTE;
        case SQL_INTERVAL_HOUR_TO_SECOND:   return SQL_C_INTERVAL_HOUR_TO_SECOND;
        case SQL_INTERVAL_MINUTE_TO_SECOND: return SQL_C_INTERVAL_MINUTE_TO_SECOND;
        case SQL_GUID:                      return SQL_C_GUID;
    }

    return SQL_C_DEFAULT;
}

bool isVerboseType(SQLSMALLINT type) noexcept {
    switch (type) {
        case SQL_DATETIME:
        case SQL_INTERVAL:
            return true;
    }

    return false;
}

bool isConciseDateTimeIntervalType(SQLSMALLINT sql_type) noexcept {
    return (!isVerboseType(sql_type) && isVerboseType(tryConvertSQLTypeToVerboseType(sql_type)));
}

bool isConciseNonDateTimeIntervalType(SQLSMALLINT sql_type) noexcept {
    return !isVerboseType(tryConvertSQLTypeToVerboseType(sql_type));
}

SQLSMALLINT tryConvertSQLTypeToVerboseType(SQLSMALLINT type) noexcept {
    switch (type) {
        case SQL_TYPE_DATE:
        case SQL_TYPE_TIME:
        case SQL_TYPE_TIMESTAMP:
            return SQL_DATETIME;

        case SQL_INTERVAL_YEAR:
        case SQL_INTERVAL_MONTH:
        case SQL_INTERVAL_DAY:
        case SQL_INTERVAL_HOUR:
        case SQL_INTERVAL_MINUTE:
        case SQL_INTERVAL_SECOND:
        case SQL_INTERVAL_YEAR_TO_MONTH:
        case SQL_INTERVAL_DAY_TO_HOUR:
        case SQL_INTERVAL_DAY_TO_MINUTE:
        case SQL_INTERVAL_DAY_TO_SECOND:
        case SQL_INTERVAL_HOUR_TO_MINUTE:
        case SQL_INTERVAL_HOUR_TO_SECOND:
        case SQL_INTERVAL_MINUTE_TO_SECOND:
            return SQL_INTERVAL;
    }

    return type;
}

SQLSMALLINT convertSQLTypeToDateTimeIntervalCode(SQLSMALLINT type) noexcept {
    switch (type) {
        case SQL_TYPE_DATE:                 return SQL_CODE_DATE;
        case SQL_TYPE_TIME:                 return SQL_CODE_TIME;
        case SQL_TYPE_TIMESTAMP:            return SQL_CODE_TIMESTAMP;
        case SQL_INTERVAL_YEAR:             return SQL_CODE_YEAR;
        case SQL_INTERVAL_MONTH:            return SQL_CODE_MONTH;
        case SQL_INTERVAL_DAY:              return SQL_CODE_DAY;
        case SQL_INTERVAL_HOUR:             return SQL_CODE_HOUR;
        case SQL_INTERVAL_MINUTE:           return SQL_CODE_MINUTE;
        case SQL_INTERVAL_SECOND:           return SQL_CODE_SECOND;
        case SQL_INTERVAL_YEAR_TO_MONTH:    return SQL_CODE_YEAR_TO_MONTH;
        case SQL_INTERVAL_DAY_TO_HOUR:      return SQL_CODE_DAY_TO_HOUR;
        case SQL_INTERVAL_DAY_TO_MINUTE:    return SQL_CODE_DAY_TO_MINUTE;
        case SQL_INTERVAL_DAY_TO_SECOND:    return SQL_CODE_DAY_TO_SECOND;
        case SQL_INTERVAL_HOUR_TO_MINUTE:   return SQL_CODE_HOUR_TO_MINUTE;
        case SQL_INTERVAL_HOUR_TO_SECOND:   return SQL_CODE_HOUR_TO_SECOND;
        case SQL_INTERVAL_MINUTE_TO_SECOND: return SQL_CODE_MINUTE_TO_SECOND;
    }

    return 0;
}

SQLSMALLINT convertDateTimeIntervalCodeToSQLType(SQLSMALLINT code, SQLSMALLINT verbose_type) noexcept {
    switch (verbose_type) {
        case SQL_DATETIME:
            switch (code) {
                case SQL_CODE_DATE:             return SQL_TYPE_DATE;
                case SQL_CODE_TIME:             return SQL_TYPE_TIME;
                case SQL_CODE_TIMESTAMP:        return SQL_TYPE_TIMESTAMP;
            }
            break;

        case SQL_INTERVAL:
            switch (code) {
                case SQL_CODE_YEAR:             return SQL_INTERVAL_YEAR;
                case SQL_CODE_MONTH:            return SQL_INTERVAL_MONTH;
                case SQL_CODE_DAY:              return SQL_INTERVAL_DAY;
                case SQL_CODE_HOUR:             return SQL_INTERVAL_HOUR;
                case SQL_CODE_MINUTE:           return SQL_INTERVAL_MINUTE;
                case SQL_CODE_SECOND:           return SQL_INTERVAL_SECOND;
                case SQL_CODE_YEAR_TO_MONTH:    return SQL_INTERVAL_YEAR_TO_MONTH;
                case SQL_CODE_DAY_TO_HOUR:      return SQL_INTERVAL_DAY_TO_HOUR;
                case SQL_CODE_DAY_TO_MINUTE:    return SQL_INTERVAL_DAY_TO_MINUTE;
                case SQL_CODE_DAY_TO_SECOND:    return SQL_INTERVAL_DAY_TO_SECOND;
                case SQL_CODE_HOUR_TO_MINUTE:   return SQL_INTERVAL_HOUR_TO_MINUTE;
                case SQL_CODE_HOUR_TO_SECOND:   return SQL_INTERVAL_HOUR_TO_SECOND;
                case SQL_CODE_MINUTE_TO_SECOND: return SQL_INTERVAL_MINUTE_TO_SECOND;
            }
            break;
    };

    return SQL_UNKNOWN_TYPE;
}

bool isIntervalCode(SQLSMALLINT code) noexcept {
    switch (code) {
        case SQL_CODE_YEAR:
        case SQL_CODE_MONTH:
        case SQL_CODE_DAY:
        case SQL_CODE_HOUR:
        case SQL_CODE_MINUTE:
        case SQL_CODE_SECOND:
        case SQL_CODE_YEAR_TO_MONTH:
        case SQL_CODE_DAY_TO_HOUR:
        case SQL_CODE_DAY_TO_MINUTE:
        case SQL_CODE_DAY_TO_SECOND:
        case SQL_CODE_HOUR_TO_MINUTE:
        case SQL_CODE_HOUR_TO_SECOND:
        case SQL_CODE_MINUTE_TO_SECOND:
            return true;
    }

    return false;
}

bool intervalCodeHasSecondComponent(SQLSMALLINT code) noexcept {
    switch (code) {
        case SQL_CODE_SECOND:
        case SQL_CODE_DAY_TO_SECOND:
        case SQL_CODE_HOUR_TO_SECOND:
        case SQL_CODE_MINUTE_TO_SECOND:
            return true;
    }

    return false;
}

bool isInputParam(SQLSMALLINT param_io_type) noexcept {
    switch (param_io_type) {
        case SQL_PARAM_INPUT:
        case SQL_PARAM_INPUT_OUTPUT:
#if (ODBCVER >= 0x0380)
        case SQL_PARAM_INPUT_OUTPUT_STREAM:
#endif
            return true;
    }

    return false;
}

bool isOutputParam(SQLSMALLINT param_io_type) noexcept {
    switch (param_io_type) {
        case SQL_PARAM_OUTPUT:
        case SQL_PARAM_INPUT_OUTPUT:
#if (ODBCVER >= 0x0380)
        case SQL_PARAM_OUTPUT_STREAM:
        case SQL_PARAM_INPUT_OUTPUT_STREAM:
#endif
            return true;
    }

    return false;
}

bool isStreamParam(SQLSMALLINT param_io_type) noexcept {
#if (ODBCVER >= 0x0380)
    switch (param_io_type) {
        case SQL_PARAM_OUTPUT_STREAM:
        case SQL_PARAM_INPUT_OUTPUT_STREAM:
            return true;
    }
#endif

    return false;
}

// TODO check if this function needs changes, I did not found a path to it
std::string convertCTypeToDataSourceType(const BoundTypeInfo & type_info) {
    LOG(__FUNCTION__);

    const auto set_nullability = [is_nullable = type_info.is_nullable] (const std::string & type_name) {
        return (is_nullable ? "Nullable(" + type_name + ")" : type_name);
    };

    std::string type_name;

    switch (type_info.c_type) {
        case SQL_C_WCHAR:
        case SQL_C_CHAR:
            type_name = set_nullability("String");
            break;

        case SQL_C_BIT:
            type_name = set_nullability("UInt8");
            break;

        case SQL_C_TINYINT:
        case SQL_C_STINYINT:
            type_name = set_nullability("Int8");
            break;

        case SQL_C_UTINYINT:
            type_name = set_nullability("UInt8");
            break;

        case SQL_C_SHORT:
        case SQL_C_SSHORT:
            type_name = set_nullability("Int16");
            break;

        case SQL_C_USHORT:
            type_name = set_nullability("UInt16");
            break;

        case SQL_C_LONG:
        case SQL_C_SLONG:
            type_name = set_nullability("int");
            break;

        case SQL_C_ULONG:
            type_name = set_nullability("UInt32");
            break;

        case SQL_C_SBIGINT:
            type_name = set_nullability("Int64");
            break;

        case SQL_C_UBIGINT:
            type_name = set_nullability("UInt64");
            break;

        case SQL_C_FLOAT:
            type_name = set_nullability("Float32");
            break;

        case SQL_C_DOUBLE:
            type_name = set_nullability("double precision");
            break;

        case SQL_C_NUMERIC:
            type_name = set_nullability("Decimal(" + std::to_string(type_info.precision) + ", " + std::to_string(type_info.scale) + ")");
            break;

        case SQL_C_BINARY:
            type_name = set_nullability(type_info.value_max_size > 0 ? ("FixedString(" + std::to_string(type_info.value_max_size) + ")") : "String");
            break;

        case SQL_C_GUID:
            type_name = set_nullability("UUID");
            break;

//      case SQL_C_BOOKMARK:
//      case SQL_C_VARBOOKMARK:

        case SQL_C_DATE:
        case SQL_C_TYPE_DATE:
            type_name = set_nullability("Date");
            break;

        case SQL_C_TIME:
        case SQL_C_TYPE_TIME:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;

        case SQL_C_TIMESTAMP:
        case SQL_C_TYPE_TIMESTAMP:
            type_name = set_nullability("timestamp");
            break;

        case SQL_C_INTERVAL_YEAR:
        case SQL_C_INTERVAL_MONTH:
        case SQL_C_INTERVAL_DAY:
        case SQL_C_INTERVAL_HOUR:
        case SQL_C_INTERVAL_MINUTE:
        case SQL_C_INTERVAL_SECOND:
        case SQL_C_INTERVAL_YEAR_TO_MONTH:
        case SQL_C_INTERVAL_DAY_TO_HOUR:
        case SQL_C_INTERVAL_DAY_TO_MINUTE:
        case SQL_C_INTERVAL_DAY_TO_SECOND:
        case SQL_C_INTERVAL_HOUR_TO_MINUTE:
        case SQL_C_INTERVAL_HOUR_TO_SECOND:
        case SQL_C_INTERVAL_MINUTE_TO_SECOND:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;
    }

    if (type_name.empty())
        throw std::runtime_error("Unable to deduce data source type from C type");

    return type_name;
}

std::string convertSQLTypeToDataSourceType(const BoundTypeInfo & type_info) {
    //syslog( LOG_INFO, "kfirkfir: in function convertSQLTypeToDataSourceType");
    const auto set_nullability = [is_nullable = type_info.is_nullable] (const std::string & type_name) {
        return (is_nullable ? "Nullable(" + type_name + ")" : type_name);
    };

    std::string type_name;

    switch (type_info.sql_type) {
        case SQL_TYPE_NULL:
            type_name = set_nullability("Nothing");
            break;

        case SQL_WCHAR:
        case SQL_CHAR:
            type_name = set_nullability("String");
            break;

        case SQL_WVARCHAR:
        case SQL_VARCHAR:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;

        case SQL_WLONGVARCHAR:
        case SQL_LONGVARCHAR:
            type_name = set_nullability("String");
            break;

        case SQL_BIT:
            type_name = set_nullability("UInt8");
            break;

        case SQL_TINYINT:
            type_name = set_nullability("Int8");
            break;

        case SQL_SMALLINT:
            type_name = set_nullability("Int16");
            break;

        case SQL_INTEGER:
            type_name = set_nullability("int");
            break;

        case SQL_BIGINT:
            type_name = set_nullability("bigint");
            break;

        case SQL_REAL:
            type_name = set_nullability("real");
            break;

        case SQL_FLOAT:
        case SQL_DOUBLE:
            type_name = set_nullability("double precision");
            break;

        case SQL_DECIMAL:
        case SQL_NUMERIC:
            type_name = set_nullability("Decimal(" + std::to_string(type_info.precision) + ", " + std::to_string(type_info.scale) + ")");
            break;

        case SQL_BINARY:
            type_name = set_nullability(type_info.value_max_size > 0 ? ("FixedString(" + std::to_string(type_info.value_max_size) + ")") : "String");
            break;

        case SQL_VARBINARY:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;

        case SQL_LONGVARBINARY:
            type_name = set_nullability("String");
            break;

        case SQL_GUID:
            type_name = set_nullability("UUID");
            break;

        case SQL_TYPE_DATE:
            type_name = set_nullability("Date");
            break;

        case SQL_TYPE_TIME:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;

        case SQL_TYPE_TIMESTAMP:
            type_name = set_nullability("timestamp");
            break;

        case SQL_INTERVAL_MONTH:
        case SQL_INTERVAL_YEAR:
        case SQL_INTERVAL_YEAR_TO_MONTH:
        case SQL_INTERVAL_DAY:
        case SQL_INTERVAL_HOUR:
        case SQL_INTERVAL_MINUTE:
        case SQL_INTERVAL_SECOND:
        case SQL_INTERVAL_DAY_TO_HOUR:
        case SQL_INTERVAL_DAY_TO_MINUTE:
        case SQL_INTERVAL_DAY_TO_SECOND:
        case SQL_INTERVAL_HOUR_TO_MINUTE:
        case SQL_INTERVAL_HOUR_TO_SECOND:
        case SQL_INTERVAL_MINUTE_TO_SECOND:
            type_name = "LowCardinality(" + set_nullability("String") + ")";
            break;
    }

    if (type_name.empty())
        throw std::runtime_error("Unable to deduce data source type from SQL type");

    return type_name;
}

std::string convertSQLOrCTypeToDataSourceType(const BoundTypeInfo & type_info) {
    try {
        return convertSQLTypeToDataSourceType(type_info);
    }
    catch (...) {
        return convertCTypeToDataSourceType(type_info);
    }
}

bool isMappedToStringDataSourceType(SQLSMALLINT sql_type, SQLSMALLINT c_type) noexcept {
    switch (sql_type) {
        case SQL_WCHAR:
        case SQL_CHAR:
        case SQL_WVARCHAR:
        case SQL_VARCHAR:
        case SQL_WLONGVARCHAR:
        case SQL_LONGVARCHAR:
        case SQL_BINARY:
        case SQL_VARBINARY:
        case SQL_LONGVARBINARY:
        case SQL_TYPE_TIME:
        case SQL_INTERVAL_MONTH:
        case SQL_INTERVAL_YEAR:
        case SQL_INTERVAL_YEAR_TO_MONTH:
        case SQL_INTERVAL_DAY:
        case SQL_INTERVAL_HOUR:
        case SQL_INTERVAL_MINUTE:
        case SQL_INTERVAL_SECOND:
        case SQL_INTERVAL_DAY_TO_HOUR:
        case SQL_INTERVAL_DAY_TO_MINUTE:
        case SQL_INTERVAL_DAY_TO_SECOND:
        case SQL_INTERVAL_HOUR_TO_MINUTE:
        case SQL_INTERVAL_HOUR_TO_SECOND:
        case SQL_INTERVAL_MINUTE_TO_SECOND:
            return true;
    }

    switch (c_type) {
        case SQL_C_WCHAR:
        case SQL_C_CHAR:
        case SQL_C_BINARY:
        case SQL_C_TIME:
        case SQL_C_TYPE_TIME:
        case SQL_C_INTERVAL_YEAR:
        case SQL_C_INTERVAL_MONTH:
        case SQL_C_INTERVAL_DAY:
        case SQL_C_INTERVAL_HOUR:
        case SQL_C_INTERVAL_MINUTE:
        case SQL_C_INTERVAL_SECOND:
        case SQL_C_INTERVAL_YEAR_TO_MONTH:
        case SQL_C_INTERVAL_DAY_TO_HOUR:
        case SQL_C_INTERVAL_DAY_TO_MINUTE:
        case SQL_C_INTERVAL_DAY_TO_SECOND:
        case SQL_C_INTERVAL_HOUR_TO_MINUTE:
        case SQL_C_INTERVAL_HOUR_TO_SECOND:
        case SQL_C_INTERVAL_MINUTE_TO_SECOND:
            return true;
    }

    return false;
}
