#include "driver/environment.h"
#include "driver/connection.h"

#include <string>

Environment::Environment(Driver & driver)
    : ChildType(driver)
{
}

const TypeInfo & Environment::getTypeInfo(const std::string & type_name, const std::string & type_name_without_parameters) const {
    const auto type_name_lower = Poco::toLower(type_name); 
    const auto type_name_without_params_lower = Poco::toLower(type_name_without_parameters); 
    auto it = types_g.find(type_name_lower);

    if (it == types_g.end())
        it = types_g.find(type_name_without_params_lower);

    if (it == types_g.end()) {
        const auto tmp_type_without_parameters_id = convertUnparametrizedTypeNameToTypeId(type_name_without_parameters);
        auto tmp_type_name = convertTypeIdToUnparametrizedCanonicalTypeName(tmp_type_without_parameters_id);

        const auto tmp_type_name_lower = Poco::toLower(tmp_type_name);
        it = types_g.find(tmp_type_name_lower);
    }

    if (it != types_g.end())
        return it->second;

    LOG("Unsupported type " << type_name << " : " << type_name_without_parameters);

    throw SqlException("Invalid SQL data type", "HY004");
}

template <>
Connection& Environment::allocateChild<Connection>() {
    auto child_sptr = std::make_shared<Connection>(*this);
    auto& child = *child_sptr;
    auto handle = child.getHandle();
    connections.emplace(handle, std::move(child_sptr));
    return child;
}

template <>
void Environment::deallocateChild<Connection>(SQLHANDLE handle) noexcept {
    connections.erase(handle);
}
