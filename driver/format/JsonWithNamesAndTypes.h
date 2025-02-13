#pragma once

#include "driver/platform/platform.h"
#include "driver/result_set.h"
#include <nlohmann/json.hpp>

using json_sax_t = nlohmann::json_sax<nlohmann::json>;

class JsonWithNamesAndTypesResultSet : public ResultSet {
public:
    JsonWithNamesAndTypesResultSet(const std::string & timezone, std::istream & stream, std::unique_ptr<ResultMutator> && mutator);
    virtual ~JsonWithNamesAndTypesResultSet() override = default;

    virtual bool readNextRow(Row & row) override;

private:
    void readValue(Field & dest, ColumnInfo & column_info, const std::string & value);
    bool isNull(const std::string & value);

    template <typename T>
    void readValueAs(Field & dest, ColumnInfo & column_info, const std::string & value) {
        T typed_value;
        readValue(typed_value, column_info, value);
        dest.data = std::move(typed_value);
    }

    void readValue(WireTypeDateAsInt & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(WireTypeDateTimeAsInt & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(WireTypeDateTime64AsInt & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Date> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::DateTime> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::DateTime64> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Decimal> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Float32> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Float64> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Int32> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Int64> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::String> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Nothing> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Boolean> & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Bytea> & dest, ColumnInfo & column_info, const std::string & value);

    template <typename T>
    void readValueUsing(T && wire_type, Field & field, ColumnInfo & column_info, const std::string & value) {
        readValue(wire_type, column_info, value);
        field.data = std::move(wire_type);
    }

    // SAX parser implementation
    class JsonHandler : public json_sax_t {
    public:
        JsonHandler(JsonWithNamesAndTypesResultSet& parent, const std::string& timezone);

        bool null() override;
        bool boolean(bool val) override;
        bool number_integer(number_integer_t val) override;
        bool number_unsigned(number_unsigned_t val) override;
        bool number_float(number_float_t val, const string_t& s) override;
        bool string(string_t& val) override;
        bool start_object(std::size_t elements) override;
        bool end_object() override;
        bool start_array(std::size_t elements) override;
        bool end_array() override;
        bool key(string_t& val) override;
        bool binary(binary_t& val) override;
        bool parse_error(std::size_t position, const std::string& last_token, const nlohmann::detail::exception& ex) override;

    private:
        JsonWithNamesAndTypesResultSet& parent_;
        const std::string& timezone_;
        std::vector<std::string> current_row_;
        std::string current_key_;
        std::string message_type_;
        bool reading_columns_ = false;
        bool reading_data_ = false;
        int array_depth_ = 0;
        bool should_stop_ = false;
        int object_depth_ = 0;
    };

    std::unique_ptr<JsonHandler> handler_;
    std::vector<std::vector<std::string>> rows_;
    size_t current_row_ = 0;
    AmortizedIStreamReader amortized_reader_;
    std::istream& json_stream_;
};

class JsonWithNamesAndTypesResultReader : public ResultReader {
public:
    JsonWithNamesAndTypesResultReader(const std::string & timezone_, std::istream & raw_stream, std::unique_ptr<ResultMutator> && mutator);
    virtual ~JsonWithNamesAndTypesResultReader() override = default;

protected:
    virtual bool advanceToNextResultSet() override;
}; 