//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#ifndef __njtls_all_policy_hpp__
#define __njtls_all_policy_hpp__

#include <botan/tls_policy.h>
#include <vector>
#include <string>

namespace njtls
{

class all_policy: virtual public Botan::TLS::Policy
{
public:
	virtual ~all_policy() = default;
public:
	all_policy() = default;
public:
	bool allow_tls12() const override {return true;}
public:
	bool allow_tls13() const override {return true;}
public:
	std::vector<std::string> allowed_ciphers() const override;
public:
	std::vector<std::string> allowed_key_exchange_methods() const override;
public:
	std::vector<std::string> allowed_signature_methods() const override;
public:
	inline std::unique_ptr<Botan::TLS::Policy> load(const std::string & policy_type);
};	// class all_policy

}	// namespace njtls

#endif	// __njtls_all_policy_hpp__

