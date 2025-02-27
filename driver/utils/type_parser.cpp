#include "driver/utils/type_parser.h"
#include "driver/utils/utils.h"

#include <sstream>

static TypeAst::Meta getTypeMeta(const std::string & name) {
    if (name == "Array") {
        return TypeAst::Array;
    }

    if (name == "Null") {
        return TypeAst::Null;
    }

    if (name == "Nullable") {
        return TypeAst::Nullable;
    }

    if (name == "Tuple") {
        return TypeAst::Tuple;
    }

    if (name == "LowCardinality") {
        return TypeAst::LowCardinality;
    }

    return TypeAst::Terminal;
}


TypeParser::TypeParser(const std::string & name) : cur_(name.data()), end_(name.data() + name.size()), type_(nullptr) {}

TypeParser::~TypeParser() = default;

bool TypeParser::parse(TypeAst * type) {
    if (!type || !cur_ || cur_ > end_)
        return false;

    // Check for "null" suffix first
    std::string type_str(cur_, end_ - cur_);
    size_t null_pos = type_str.find(" null");
    bool has_null_suffix = (null_pos != std::string::npos);
    
    if (has_null_suffix) {
        // Treat the part before " null" as the type name
        type_str = type_str.substr(0, null_pos);
        cur_ = type_str.c_str();
        end_ = cur_ + type_str.length();
        type->nullable = true;
    }

    type_ = type;
    open_elements_.push(type_);

    do {
        const Token & token = nextToken();

        switch (token.type) {
            case Token::Name:
                type_->meta = getTypeMeta(token.value);
                type_->name = token.value;
                break;
            case Token::Number:
                type_->meta = TypeAst::Number;
                type_->size = fromString<int>(token.value);
                break;
            case Token::LPar:
                type_->elements.emplace_back(TypeAst());
                open_elements_.push(type_);
                type_ = &type_->elements.back();
                break;
            case Token::RPar:
                type_ = open_elements_.top();
                open_elements_.pop();
                break;
            case Token::Comma:
                type_ = open_elements_.top();
                open_elements_.pop();
                type_->elements.emplace_back(TypeAst());
                open_elements_.push(type_);
                type_ = &type_->elements.back();
                break;
            case Token::EOS:
                return true;
            case Token::Invalid:
                return false;
        }
    } while (true);

    // If we found a null suffix, modify the type name to include it
    if (has_null_suffix && type_->meta == TypeAst::Terminal) {
        type_->name = type_->name + " null";
    }

    return true;
}

TypeParser::Token TypeParser::nextToken() {
    for (; cur_ < end_; ++cur_) {
        switch (*cur_) {
            case '\n':
            case '\t':
            case '\0':
                continue;

            case ' ': {
                // Check if this space is part of a compound type name
                const char* next = cur_ + 1;
                while (next < end_ && *next == ' ') next++; // Skip multiple spaces
                if (next < end_ && isalpha(*next)) {
                    // Look ahead to see if this is a known compound type
                    std::string compound = std::string(cur_ - 10, std::min(next + 10, end_));
                    if (compound.find("double precision") != std::string::npos ||
                        compound.find("character varying") != std::string::npos) {
                        continue; // Keep the space for compound types
                    }
                }
                continue; // Skip space otherwise
            }

            case '(':
                return Token {Token::LPar, std::string(cur_++, 1)};
            case ')':
                return Token {Token::RPar, std::string(cur_++, 1)};
            case ',':
                return Token {Token::Comma, std::string(cur_++, 1)};

            default: {
                const char * st = cur_;

                if (*cur_ == '"' || *cur_ == '\'') {
                    for (++cur_; cur_ < end_; ++cur_) {
                        if (*cur_ == *st) {
                            break;
                        }
                    }

                    if (cur_ == end_)
                        return Token {Token::Invalid, std::string()};

                    return Token {Token::Name, std::string(st + 1, cur_++)};
                }

                if (isalpha(*cur_)) {
                    for (; cur_ < end_; ++cur_) {
                        // Allow spaces within known compound types
                        if (cur_ + 1 < end_ && *cur_ == ' ' && isalpha(*(cur_ + 1))) {
                            std::string partial = std::string(st, cur_ + 10);
                            if (partial.find("double precision") == 0 ||
                                partial.find("character varying") == 0) {
                                continue;
                            }
                        }
                        if (!isalpha(*cur_) && !isdigit(*cur_) && *cur_ != ' ') {
                            break;
                        }
                    }

                    std::string token(st, cur_);
                    // Trim any trailing spaces
                    while (!token.empty() && token.back() == ' ') {
                        token.pop_back();
                    }
                    return Token {Token::Name, token};
                }

                if (isdigit(*cur_)) {
                    for (; cur_ < end_; ++cur_) {
                        if (!isdigit(*cur_)) {
                            break;
                        }
                    }

                    return Token {Token::Number, std::string(st, cur_)};
                }

                return Token {Token::Invalid, std::string()};
            }
        }
    }

    return Token {Token::EOS, std::string()};
}
