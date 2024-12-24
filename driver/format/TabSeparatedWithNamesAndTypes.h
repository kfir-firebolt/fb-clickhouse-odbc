#pragma once

#include "driver/platform/platform.h"
#include "driver/result_set.h"

// Implementation of ResultSet for TabSeparatedWithNamesAndTypes wire format of ClickHouse.
class TabSeparatedWithNamesAndTypesResultSet
    : public ResultSet
{
public:
    explicit TabSeparatedWithNamesAndTypesResultSet(const std::string & timezone, AmortizedIStreamReader & stream, std::unique_ptr<ResultMutator> && mutator);
    virtual ~TabSeparatedWithNamesAndTypesResultSet() override = default;

protected:
    virtual bool readNextRow(Row & row) override;

private:
    bool eol() const;
    void readString(std::string & dest);
    void readNames();
    static bool isNull(const std::string & value);

    // void readValue(bool & dest);
    // void readValue(std::string & dest);
    // void readValue(std::string & dest, const std::uint64_t size);

    template <typename T>
    void readPOD(T & dest) {
        stream.read(reinterpret_cast<char *>(&dest), sizeof(T));
    }

    void readValue(Field & dest, ColumnInfo & column_info, const std::string & value);

    template <typename T>
    void readValueUsing(T && value, Field & dest, ColumnInfo & column_info, const std::string & value_) {
        readValue(value, column_info, value_);
        dest.data = std::forward<T>(value);
    }

    template <typename T>
    void readValueAs(Field & dest, ColumnInfo & column_info, const std::string & value) {
        return readValueUsing(T(), dest, column_info, value);
    }

    void readValue(WireTypeDateAsInt & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(WireTypeDateTimeAsInt & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(WireTypeDateTime64AsInt & dest, ColumnInfo & column_info, const std::string & value);

    void readValue(DataSourceType< DataSourceTypeId::Date        > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::DateTime    > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::DateTime64  > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Decimal     > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Decimal32   > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Decimal64   > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Decimal128  > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType<DataSourceTypeId::Float32      > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Float64     > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Int32       > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Int64       > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Nothing     > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::String      > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Boolean     > & dest, ColumnInfo & column_info, const std::string & value);
    void readValue(DataSourceType< DataSourceTypeId::Bytea       > & dest, ColumnInfo & column_info, const std::string & value);

    template <typename T>
    void readValue(T & dest, ColumnInfo & column_info) {
        throw std::runtime_error("Unable to decode value of type2 '" + column_info.type + "'");
    }
};

class TabSeparatedWithNamesAndTypesResultReader
    : public ResultReader
{
public:
    explicit TabSeparatedWithNamesAndTypesResultReader(const std::string & timezone, std::istream & raw_stream, std::unique_ptr<ResultMutator> && mutator);
    virtual ~TabSeparatedWithNamesAndTypesResultReader() override = default;

    virtual bool advanceToNextResultSet() override;
};
