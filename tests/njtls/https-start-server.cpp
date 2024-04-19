//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#define BOOST_TEST_MODULE "https-start-server.cpp"
#include <boost/test/unit_test.hpp>
#include <njtls/all_policy.hpp>
#include <njtls/credman.hpp>
#include <botan/auto_rng.h>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <botan/tls_session_manager_noop.h>

namespace btls = Botan::TLS;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using asio::ip::tcp;

BOOST_AUTO_TEST_CASE(https_start_server_01)
{
	std::cout << "------------------------------------------------------------\n";
	std::cout << "---- https_start-server ----" << std::endl;
	{
		Botan::AutoSeeded_RNG rng;
		asio::io_context io_context{2};
		btls::Session_Manager_Noop session_man;
		njtls::all_policy policy;
		njtls::credman credman;
	}
}

