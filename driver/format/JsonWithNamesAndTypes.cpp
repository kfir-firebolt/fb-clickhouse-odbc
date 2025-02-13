#include "driver/format/JsonWithNamesAndTypes.h"
#include "driver/utils/resize_without_initialization.h"
#include <ctime>
#include <iostream>
#include <driver/driver.h>

JsonWithNamesAndTypesResultSet::JsonHandler::JsonHandler(JsonWithNamesAndTypesResultSet& parent, const std::string& timezone)
    : parent_(parent)
    , timezone_(timezone) {}

bool JsonWithNamesAndTypesResultSet::JsonHandler::null() {
    if (reading_data_) {
        current_row_.push_back("\\N");
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::boolean(bool val) {
    if (reading_data_) {
        current_row_.push_back(val ? "t" : "f");
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::number_integer(number_integer_t val) {
    if (reading_data_) {
        current_row_.push_back(std::to_string(val));
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::number_unsigned(number_unsigned_t val) {
    if (reading_data_) {
        current_row_.push_back(std::to_string(val));
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::number_float(number_float_t val, const string_t& s) {
    if (reading_data_) {
        current_row_.push_back(s);
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::string(string_t& val) {
    LOG("Processing string value: '" + val + "' for key: '" + current_key_ + "'");
    if (current_key_ == "message_type") {
        message_type_ = val;
        reading_columns_ = (val == "START");
        reading_data_ = (val == "DATA");
        LOG("Message type: " + message_type_ + ", reading_columns_: " + std::to_string(reading_columns_) + ", reading_data_: " + std::to_string(reading_data_));
    } else if (reading_columns_ && current_key_ == "name") {
        ColumnInfo info;
        info.name = val;
        parent_.columns_info.push_back(info);
        LOG("Added column name: " + val);
    } else if (reading_columns_ && current_key_ == "type") {
        if (!parent_.columns_info.empty()) {
            auto& column = parent_.columns_info.back();
            column.type = val;
            LOG("Processing column type: " + val + " for column: " + column.name);
            TypeParser parser{column.type};
            TypeAst ast;
            if (parser.parse(&ast)) {
                column.assignTypeInfo(ast, timezone_);
                LOG("Parsed type info successfully");
                if (convertUnparametrizedTypeNameToTypeId(column.type_without_parameters) == DataSourceTypeId::Unknown) {
                    column.type_without_parameters = "String";
                    LOG("Unknown type converted to String");
                }
            } else {
                column.type_without_parameters = "String";
                LOG("Failed to parse type, defaulting to String");
            }
            column.updateTypeInfo();
        }
    } else if (reading_data_) {
        current_row_.push_back(val);
        LOG("Added value to current row: " + val);
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::start_object(std::size_t elements) {
    object_depth_++;
    LOG("Start object at depth: " + std::to_string(object_depth_));
    
    if (object_depth_ == 1) {  // Root object
        reading_columns_ = false;
        reading_data_ = false;
        should_stop_ = false;
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::end_object() {
    LOG("End object at depth: " + std::to_string(object_depth_) + ", message_type: " + message_type_);
    
    // Only process message completion at root level
    if (object_depth_ == 1 && !message_type_.empty()) {
        if (message_type_ == "START") {
            reading_columns_ = false;
        } else if (message_type_ == "DATA") {
            reading_data_ = false;
        } else if (message_type_ == "FINISH_SUCCESSFULLY") {
            should_stop_ = true;  // Signal to stop parsing after this object
        }
        should_stop_ = true;  // Signal to stop parsing after this object
        message_type_.clear();
    }
    
    object_depth_--;
    return !should_stop_;  // Return false to stop parsing
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::start_array(std::size_t elements) {
    if (reading_data_) {
        array_depth_++;
        LOG("Start array at depth: " + std::to_string(array_depth_));
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::end_array() {
    if (reading_data_) {
        LOG("End array at depth: " + std::to_string(array_depth_));
        if (array_depth_ == 2) {
            if (!current_row_.empty()) {
                parent_.rows_.push_back(std::move(current_row_));
                LOG("Added row with " + std::to_string(current_row_.size()) + " fields");
                current_row_.clear();
            }
        }
        array_depth_--;
    }
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::key(string_t& val) {
    current_key_ = val;
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::binary(binary_t& val) {
    return true;
}

bool JsonWithNamesAndTypesResultSet::JsonHandler::parse_error(std::size_t position, 
    const std::string& last_token, const nlohmann::detail::exception& ex) {
    throw std::runtime_error("JSON parse error at position " + std::to_string(position) + 
        ": " + ex.what());
    return false;
}

JsonWithNamesAndTypesResultSet::JsonWithNamesAndTypesResultSet(
    const std::string & timezone, 
    std::istream & stream,
    std::unique_ptr<ResultMutator> && mutator)
    : amortized_reader_(stream)
    , ResultSet(amortized_reader_, std::move(mutator))
    , json_stream_(stream)
{
    LOG("Initializing JSON parser");
    handler_ = std::make_unique<JsonHandler>(*this, timezone);
    
    size_t iterations = 0;
    while (!json_stream_.eof() && !json_stream_.fail() && iterations++ < 3) {
        try {
            LOG("Starting to parse JSON object");
            nlohmann::json::sax_parse(json_stream_, handler_.get());
//                LOG("Parsing stopped by handler");
//                break;  // Stop if handler returns false
            LOG("Finished parsing JSON object");
        } catch (const nlohmann::detail::parse_error& e) {
            LOG("Parse error: " + std::string(e.what()) + " (id: " + std::to_string(e.id) + ")");
            if (e.id != 101) { // Not an EOF error
                throw;
            }
            LOG("Continuing to next JSON object");
        }
    }
    
    finished = columns_info.empty();
    LOG("Initialization complete. Columns: " + std::to_string(columns_info.size()) + 
        ", Rows: " + std::to_string(rows_.size()));
}

bool JsonWithNamesAndTypesResultSet::readNextRow(Row & row) {
    if (current_row_ >= rows_.size()) {
        LOG("No more rows to read");
        return false;
    }

    const auto& current_row_data = rows_[current_row_];
    LOG("Reading row " + std::to_string(current_row_) + " with " + std::to_string(current_row_data.size()) + " fields");
    
    for (size_t i = 0; i < row.fields.size(); ++i) {
        if (i < current_row_data.size()) {
            LOG("Reading field " + std::to_string(i) + ": " + current_row_data[i]);
            readValue(row.fields[i], columns_info[i], current_row_data[i]);
        }
    }
    
    current_row_++;
    return true;
}

bool JsonWithNamesAndTypesResultSet::isNull(const std::string & value) {
    return value == "\\N";
}

void JsonWithNamesAndTypesResultSet::readValue(Field & dest, ColumnInfo & column_info, const std::string & value) {
    auto value_ = string_pool.get();
    value_manip::to_null(value_);

    if (isNull(value)) {
        dest.data = DataSourceType<DataSourceTypeId::Nothing>{};
        string_pool.put(std::move(value_));
        return;
    }

    constexpr bool convert_on_fetch_conservatively = true;

    if (convert_on_fetch_conservatively) switch (column_info.type_without_parameters_id) {
        case DataSourceTypeId::Date:        return readValueUsing(WireTypeDateAsInt(column_info.timezone), dest, column_info, value);
        case DataSourceTypeId::Timestamp:    return readValueUsing(WireTypeDateTimeAsInt(column_info.timezone), dest, column_info, value);
        case DataSourceTypeId::TimestampTz:  return readValueUsing(WireTypeDateTime64AsInt(column_info.precision, column_info.timezone), dest, column_info, value);
        default:                            break;
    }

    switch (column_info.type_without_parameters_id) {
        case DataSourceTypeId::Date:        return readValueAs<DataSourceType<DataSourceTypeId::Date>>(dest, column_info, value);
        case DataSourceTypeId::Timestamp:    return readValueAs<DataSourceType<DataSourceTypeId::Timestamp>>(dest, column_info, value);
        case DataSourceTypeId::TimestampTz:  return readValueAs<DataSourceType<DataSourceTypeId::TimestampTz>>(dest, column_info, value);
        case DataSourceTypeId::Decimal:     return readValueAs<DataSourceType<DataSourceTypeId::Decimal>>(dest, column_info, value);
        case DataSourceTypeId::Decimal32:   return readValueAs<DataSourceType<DataSourceTypeId::Decimal32>>(dest, column_info, value);
        case DataSourceTypeId::Decimal64:   return readValueAs<DataSourceType<DataSourceTypeId::Decimal64>>(dest, column_info, value);
        case DataSourceTypeId::Decimal128:  return readValueAs<DataSourceType<DataSourceTypeId::Decimal128>>(dest, column_info, value);
        case DataSourceTypeId::Float32:     return readValueAs<DataSourceType<DataSourceTypeId::Float32>>(dest, column_info, value);
        case DataSourceTypeId::Float64:     return readValueAs<DataSourceType<DataSourceTypeId::Float64>>(dest, column_info, value);
        case DataSourceTypeId::Int32:       return readValueAs<DataSourceType<DataSourceTypeId::Int32>>(dest, column_info, value);
        case DataSourceTypeId::Int64:       return readValueAs<DataSourceType<DataSourceTypeId::Int64>>(dest, column_info, value);
        case DataSourceTypeId::Nothing:     return readValueAs<DataSourceType<DataSourceTypeId::Nothing>>(dest, column_info, value);
        case DataSourceTypeId::String:      return readValueAs<DataSourceType<DataSourceTypeId::String>>(dest, column_info, value);
        case DataSourceTypeId::Boolean:     return readValueAs<DataSourceType<DataSourceTypeId::Boolean>>(dest, column_info, value);
        case DataSourceTypeId::Bytea:       return readValueAs<DataSourceType<DataSourceTypeId::Bytea>>(dest, column_info, value);
        default:                            throw std::runtime_error("Unable to decode value of type '" + column_info.type + "'");
    }
}

void JsonWithNamesAndTypesResultSet::readValue(WireTypeDateAsInt & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoi(value);
}

void JsonWithNamesAndTypesResultSet::readValue(WireTypeDateTimeAsInt & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoll(value);
}

void JsonWithNamesAndTypesResultSet::readValue(WireTypeDateTime64AsInt & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoll(value);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Date> & dest, ColumnInfo & column_info, const std::string & value) {
    value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::Date>>::convert(value, dest);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Timestamp> & dest, ColumnInfo & column_info, const std::string & value) {
    value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::Timestamp>>::convert(value, dest);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::TimestampTz> & dest, ColumnInfo & column_info, const std::string & value) {
    value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::TimestampTz>>::convert(value, dest);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Decimal> & dest, ColumnInfo & column_info, const std::string & value) {
    value_manip::from_value<std::string>::template to_value<DataSourceType<DataSourceTypeId::Decimal>>::convert(value, dest);
    dest.precision = column_info.precision;
    dest.scale = column_info.scale;
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Float32> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stof(value);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Float64> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stod(value);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Int32> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoi(value);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Int64> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = std::stoll(value);
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::String> & dest, ColumnInfo & column_info, const std::string & value) {
    if (dest.value.capacity() <= initial_string_capacity_g) {
        dest.value = string_pool.get();
        value_manip::to_null(dest.value);
    }
    dest.value = value;
    if (column_info.display_size_so_far < dest.value.size())
        column_info.display_size_so_far = dest.value.size();
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Nothing> & dest, ColumnInfo & column_info, const std::string & value) {
    // Do nothing
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Boolean> & dest, ColumnInfo & column_info, const std::string & value) {
    if (value == "f") {
        dest.value = false;
    } else if (value == "t") {
        dest.value = true;
    } else {
        throw std::runtime_error("Unable to decode value of type 'BOOLEAN' from '" + value + "'");
    }
}

void JsonWithNamesAndTypesResultSet::readValue(DataSourceType<DataSourceTypeId::Bytea> & dest, ColumnInfo & column_info, const std::string & value) {
    dest.value = value.substr(2);
}

JsonWithNamesAndTypesResultReader::JsonWithNamesAndTypesResultReader(
    const std::string & timezone_,
    std::istream & raw_stream,
    std::unique_ptr<ResultMutator> && mutator)
    : ResultReader(timezone_, raw_stream, std::move(mutator))
{
    if (raw_stream.eof() || raw_stream.fail())
        return;

    result_set = std::make_unique<JsonWithNamesAndTypesResultSet>(timezone_, raw_stream, releaseMutator());
}

bool JsonWithNamesAndTypesResultReader::advanceToNextResultSet() {
    if (result_set) {
        result_mutator = result_set->releaseMutator();
        result_set.reset();
    }
    return hasResultSet();
} 