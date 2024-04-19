//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#define BOOST_TEST_MODULE "njtls-all_policy.cpp"
#include <boost/test/unit_test.hpp>
#include <njtls/njtls.hpp>
#include <iostream>

BOOST_AUTO_TEST_CASE(njtls_all_policy_01)
{
	std::cout << "------------------------------------------------------------\n";
	std::cout << "---- njtls::all_policy ----" << std::endl;
	{
		njtls::all_policy tls_policy;
		BOOST_CHECK(tls_policy.allow_tls12());
		BOOST_CHECK(tls_policy.allow_tls13());
		for (const std::string_view view: tls_policy.allowed_ciphers())
			std::cout << "allowed cipher: " << view << std::endl;
		for (const std::string_view view: tls_policy.allowed_key_exchange_methods())
			std::cout << "allowed key exchange methods: " << view << std::endl;
		for (const std::string_view view: tls_policy.allowed_signature_methods())
			std::cout << "allowed signature methods: " << view << std::endl;
	}
}

