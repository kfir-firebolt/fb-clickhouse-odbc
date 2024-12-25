#include <iostream>
#include <odbc/Connection.h>
#include <odbc/Environment.h>
#include <odbc/Exception.h>
#include <odbc/PreparedStatement.h>
#include <odbc/ResultSet.h>
#include <odbc/ResultSetMetaData.h>
#include <odbc/ResultSetMetaDataBase.h>
#include <gtest/gtest.h>
#include <filesystem>
#include <cstdlib>

TEST(FBTypes, Literals) {
odbc::EnvironmentRef env = odbc::Environment::create();

  odbc::ConnectionRef pg_conn = env->createConnection();
  pg_conn->connect("DRIVER={PostgreSQL ANSI};"
                   "DATABASE=postgres;"
                   "UID=kfir;"
                   "PWD=password;"
                   "SERVER=localhost;"
                   "PORT=5432;");


  const char* sa_id = getenv("SA_ID");
  const char* sa_pwd = getenv("SA_PWD");
  std::string conn_str = "DRIVER={ClickHouse ODBC Driver (ANSI)};UID=" + std::string(sa_id) + ";PWD=" + std::string(sa_pwd) + ";SERVER=STAGING;ACCOUNT=developer";

  odbc::ConnectionRef fb_conn = env->createConnection();
  fb_conn->connect(conn_str.c_str());

  std::vector<std::string> queries = {
      "select 3::int;",       // int
      "select 3::bigint;",    // bigint
      "select 3.4::real;",    // real
      "select 3.4::float;",   // float
      "select true;",         // bool
      "select false;",         // bool
      "select 'hello';",      // text
      "select 'a'::bytea;",   // bytea
      "select '{1}'::int[];", // array(int)
      "select 3::numeric;",   // numeric
      "select 3::decimal;",   // numeric
      "select 3::numeric(1,0);",   // numeric
      "select 3.5::numeric(5,2);",   // numeric
      "select 3.54::numeric(10,3);",   // numeric
      "select 3.234::numeric(20,10);",   // numeric
      "select '12345678.12345678901234567890123456789'::numeric(38,30);",   // numeric
      "select 3::numeric(40,0);",   // numeric
  };
  for (const auto &query : queries) {
    std::cout << "\n" << query << std::endl;
    std::vector<std::string> fb_results;
    std::vector<std::string> pg_results;
    std::string error;
    for (auto conn : {pg_conn, fb_conn}) {
      const bool is_fb = &*conn == &*fb_conn;
      std::cout << "\n" << (is_fb ? "FB:" : "PG:") << std::endl;
      try {
        odbc::ResultSetRef rs =
            conn->prepareStatement(query.c_str())->executeQuery();
        while (rs->next()) {
          (is_fb ? fb_results : pg_results).push_back("DataType name: " + rs->getMetaData().get()->getColumnTypeName(1));
          (is_fb ? fb_results : pg_results).push_back("DataType id: " + std::to_string((int)rs->getMetaData().get()->getColumnType(1)));
          std::stringstream ss;
          ss << "Value as string: " << rs->getString(1);
          (is_fb ? fb_results : pg_results).push_back(ss.str());

          for (const auto& result : (is_fb ? fb_results : pg_results)) {
            std::cout << result << std::endl;
          }
        }
      } catch (std::exception & e) {
        error = "Error while executing " + std::string(is_fb ? "FB:" : "PG:") + e.what();
        std::cout << error << std::endl;
      }
    }
    EXPECT_EQ(fb_results.size(), pg_results.size()) << error;
    if (fb_results.size() == pg_results.size()) {
      for (size_t i = 0; i < fb_results.size(); ++i) {
        EXPECT_EQ(fb_results[i], pg_results[i]) << "wrong results for query: " << query;
      }
    }
  }
}
