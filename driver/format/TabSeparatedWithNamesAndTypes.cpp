#include "driver/format/TabSeparatedWithNamesAndTypes.h"
#include "driver/utils/resize_without_initialization.h"
#include <ctime>
#include <sys/syslog.h>


bool TabSeparatedWithNamesAndTypesResultSet::eol() const {
    if (stream.top() == '\n') {
        return true;
    }
    return false;
}

void TabSeparatedWithNamesAndTypesResultSet::readString(std::string & out) {
    while (!eol()) {
        const char c = stream.get();
        if (c == '\t') {
            syslog( LOG_INFO, "kfirkfir: in function readString \\t: %s", out.c_str());
            return;
        }
        if (c == '\\') {
            const char cc = stream.get();
            if (cc == 't') {
                out.push_back('\t');
            } else if (cc == 'n') {
                out.push_back('\n');
            } else if (cc == '\\') {
                out.push_back('\\');
            } else if (cc == 'r') {
                out.push_back('\r');
            } else {
                out.push_back(c);
                out.push_back(cc);
            }
        } else {
            out.push_back(c);
        }
    }
    syslog( LOG_INFO, "kfirkfir: in function readString eol: %s", out.c_str());
}

void TabSeparatedWithNamesAndTypesResultSet::readNames() {
    std::vector<std::string> names;
    while (!eol()) {
        std::string name;
        readString(name);
        syslog( LOG_INFO, "kfirkfir: in function readNames:read a name: %s", name.c_str());
        names.push_back(std::move(name));

    }
    // Skip the newline character.
    // TODO make sure it works with \r\n, \r, \n
    stream.get();

    const size_t num_columns = names.size();
    columns_info.resize(num_columns);
    for (std::size_t i = 0; i < num_columns; ++i) {
        columns_info[i].name = names[i];
    }
}

TabSeparatedWithNamesAndTypesResultSet::TabSeparatedWithNamesAndTypesResultSet(const std::string & timezone, AmortizedIStreamReader & stream, std::unique_ptr<ResultMutator> && mutator)
    : ResultSet(stream, std::move(mutator))
{
    readNames();
    const std::uint64_t num_columns = columns_info.size();

    for (std::size_t i = 0; i < num_columns; ++i) {
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:Ctor1");

        readString(columns_info[i].type);


        TypeParser parser{columns_info[i].type};
        TypeAst ast;

        if (parser.parse(&ast)) {
            columns_info[i].assignTypeInfo(ast, timezone);

            if (convertUnparametrizedTypeNameToTypeId(columns_info[i].type_without_parameters) == DataSourceTypeId::Unknown) {
                // Interpret all unknown types as String.
                columns_info[i].type_without_parameters = "String";
            }
        }
        else {
            // Interpret all unparsable types as String.
            columns_info[i].type_without_parameters = "String";
        }
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:Ctor2");


        columns_info[i].updateTypeInfo();
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:Ctor3 %s", columns_info[i].type_without_parameters.c_str());
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:Ctor3 %d", columns_info[i].type_without_parameters_id);
    }

    finished = columns_info.empty();
}

bool TabSeparatedWithNamesAndTypesResultSet::readNextRow(Row & row) {
    syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:readNextRow start");

    if (stream.eof())
        return false;
    syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:readNextRow start2");

    for (std::size_t i = 0; i < row.fields.size(); ++i) {
        if (eol()) {
            stream.get();
        }
        std::string value;
        readString(value);
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:readNextRow %s", value.c_str());
        readValue(row.fields[i], columns_info[i], value);
        syslog( LOG_INFO, "kfirkfir: in function TabSeparatedWithNamesAndTypesResultSet:readNextRow finish %lu", i);
    }
    if (eol()) {
        stream.get();
    }

    return true;
}


bool TabSeparatedWithNamesAndTypesResultSet::isNull(const std::string & value) {
    return value == "\\N";
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(Field & dest, ColumnInfo & column_info, const std::string & value) {
    syslog( LOG_INFO, "kfirkfir: in function readValue: %s", value.c_str());

    auto value_ = string_pool.get();
    value_manip::to_null(value_);

    if (isNull(value)) {
        syslog( LOG_INFO, "kfirkfir: in function readValue: decided nothing");
        dest.data = DataSourceType<DataSourceTypeId::Nothing>{};
        string_pool.put(std::move(value_));
        return;
    }

    constexpr bool convert_on_fetch_conservatively = true;

    if (convert_on_fetch_conservatively) switch (column_info.type_without_parameters_id) {
        case DataSourceTypeId::Date:        return readValueUsing( WireTypeDateAsInt       (column_info.timezone),                        dest, column_info, value);
        case DataSourceTypeId::DateTime:    return readValueUsing( WireTypeDateTimeAsInt   (column_info.timezone),                        dest, column_info, value);
        case DataSourceTypeId::DateTime64:  return readValueUsing( WireTypeDateTime64AsInt (column_info.precision, column_info.timezone), dest, column_info, value);
        default:                            break; // Continue with the next complete switch...
    }

    switch (column_info.type_without_parameters_id) {
        case DataSourceTypeId::Date:        return readValueAs<DataSourceType< DataSourceTypeId::Date        >>(dest, column_info, value);
        case DataSourceTypeId::DateTime:    return readValueAs<DataSourceType< DataSourceTypeId::DateTime    >>(dest, column_info, value);
        case DataSourceTypeId::DateTime64:  return readValueAs<DataSourceType< DataSourceTypeId::DateTime64  >>(dest, column_info, value);
        case DataSourceTypeId::Decimal:     return readValueAs<DataSourceType< DataSourceTypeId::Decimal     >>(dest, column_info, value);
        case DataSourceTypeId::Decimal32:   return readValueAs<DataSourceType< DataSourceTypeId::Decimal32   >>(dest, column_info, value);
        case DataSourceTypeId::Decimal64:   return readValueAs<DataSourceType< DataSourceTypeId::Decimal64   >>(dest, column_info, value);
        case DataSourceTypeId::Decimal128:  return readValueAs<DataSourceType< DataSourceTypeId::Decimal128  >>(dest, column_info, value);
        case DataSourceTypeId::Float32:     return readValueAs<DataSourceType< DataSourceTypeId::Float32     >>(dest, column_info, value);
        case DataSourceTypeId::Float64:     return readValueAs<DataSourceType< DataSourceTypeId::Float64     >>(dest, column_info, value);
        case DataSourceTypeId::Int32:       return readValueAs<DataSourceType< DataSourceTypeId::Int32       >>(dest, column_info, value);
        case DataSourceTypeId::Int64:       return readValueAs<DataSourceType< DataSourceTypeId::Int64       >>(dest, column_info, value);
        case DataSourceTypeId::Nothing:     return readValueAs<DataSourceType< DataSourceTypeId::Nothing     >>(dest, column_info, value);
        case DataSourceTypeId::String:      return readValueAs<DataSourceType< DataSourceTypeId::String      >>(dest, column_info, value);
        case DataSourceTypeId::Boolean:     return readValueAs<DataSourceType< DataSourceTypeId::Boolean     >>(dest, column_info, value);
        case DataSourceTypeId::Bytea:       return readValueAs<DataSourceType< DataSourceTypeId::Bytea       >>(dest, column_info, value);
        default:                            throw std::runtime_error("Unable to decode value of type1 '" + column_info.type + "'. enum id: " + std::to_string((int)column_info.type_without_parameters_id));
    }
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(WireTypeDateAsInt & dest, ColumnInfo & column_info, const std::string & value) {
    // readPOD(dest.value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(WireTypeDateTimeAsInt & dest, ColumnInfo & column_info, const std::string & value) {
    // readPOD(dest.value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(WireTypeDateTime64AsInt & dest, ColumnInfo & column_info, const std::string & value) {
    // readPOD(dest.value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Date> & dest, ColumnInfo & column_info, const std::string & value) {
    WireTypeDateAsInt dest_raw(column_info.timezone);
    // readValue(dest_raw, column_info);
    value_manip::from_value<decltype(dest_raw)>::template to_value<decltype(dest)>::convert(dest_raw, dest);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::DateTime> & dest, ColumnInfo & column_info, const std::string & value) {
    WireTypeDateTimeAsInt dest_raw(column_info.timezone);
    // readValue(dest_raw, column_info);
    value_manip::from_value<decltype(dest_raw)>::template to_value<decltype(dest)>::convert(dest_raw, dest);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::DateTime64> & dest, ColumnInfo & column_info, const std::string & value) {
    WireTypeDateTime64AsInt dest_raw(column_info.precision, column_info.timezone);
    // readValue(dest_raw, column_info);
    value_manip::from_value<decltype(dest_raw)>::template to_value<decltype(dest)>::convert(dest_raw, dest);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Decimal> & dest, ColumnInfo & column_info, const std::string & value) {
    value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::Decimal>>::convert(value, dest);

    // Override the CH implementation of the conversion to support the full range of decimal always (don't shrink the value)
    dest.precision = column_info.precision;
    dest.scale = column_info.scale;
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Float32> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stof(value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Float64> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stod(value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Int32> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoi(value);
    // TODO check if this method is better for all numeric datatypes
    // return value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::Int32>>::convert(value, dest);

}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Int64> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stol(value);
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Nothing> & dest, ColumnInfo & column_info, const std::string & value) {
    // Do nothing.
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::String> & dest, ColumnInfo & column_info, const std::string & value) {
    if (dest.value.capacity() <= initial_string_capacity_g) {
        dest.value = string_pool.get();
        value_manip::to_null(dest.value);
    }

    dest.value = value;

    if (column_info.display_size_so_far < dest.value.size())
        column_info.display_size_so_far = dest.value.size();
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Boolean> & dest, ColumnInfo & column_info, const std::string & value) {
    syslog( LOG_INFO, "kfirkfir: in function readValue BOOLEAN: %s", value.c_str());
    if (value == "f") {
        dest.value = false;
    } else if (value == "t") {
        dest.value = true;
    } else {
        throw std::runtime_error("Unable to decode value of type 'BOOLEAN' from '" + value + "'");
    }
}

void TabSeparatedWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Bytea> & dest, ColumnInfo & column_info, const std::string & value) {
    syslog( LOG_INFO, "kfirkfir: in function readValue bytea: %s", value.c_str());
    dest.value = value.substr(2);
}

TabSeparatedWithNamesAndTypesResultReader::TabSeparatedWithNamesAndTypesResultReader(const std::string & timezone_, std::istream & raw_stream, std::unique_ptr<ResultMutator> && mutator)
    : ResultReader(timezone_, raw_stream, std::move(mutator))
{
    if (stream.eof())
        return;

    result_set = std::make_unique<TabSeparatedWithNamesAndTypesResultSet>(timezone, stream, releaseMutator());
}

bool TabSeparatedWithNamesAndTypesResultReader::advanceToNextResultSet() {
    // TabSeparatedWithNamesAndTypes format doesn't support multiple result sets in the response,
    // so only a basic cleanup is done here.

    if (result_set) {
        result_mutator = result_set->releaseMutator();
        result_set.reset();
    }

    return hasResultSet();
}
