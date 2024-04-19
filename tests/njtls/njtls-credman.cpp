//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#define BOOST_TEST_MODULE "njtls-credman.cpp"
#include <boost/test/unit_test.hpp>
#include <njtls/credman.hpp>
#include <iostream>
#include <botan/auto_rng.h>
#include <filesystem>

namespace fs = std::filesystem;
using std::string_literals::operator""s;

BOOST_AUTO_TEST_CASE(njtls_credman_01)
{
	std::cout << "------------------------------------------------------------" << std::endl;
	std::cout << "---- njtls::credman ----" << std::endl;
	{
		try
		{
			std::cout << "fs::current_path: " << fs::current_path() << std::endl;
			njtls::credman cm1;
			Botan::AutoSeeded_RNG rng;

			fs::path cert_filename = "cake.cert";
			fs::path key_filename = "cake.key";
		
			if (! fs::exists(fs::path{"/tmp"} / cert_filename) || ! fs::exists(fs::path{"/tmp"} / key_filename))
			{
				BOOST_CHECK_MESSAGE(false,
					"Please copy "s + cert_filename.string() + ", " + key_filename.string()
						+ " to /tmp/, and run test again! (These files are commonly generated at dir test-certs-data/ ; after testing, you can remove those temporary files.");
				BOOST_REQUIRE(false);
			}
		
			cert_filename = fs::path{"/tmp"} / cert_filename;
			key_filename = fs::path{"/tmp"} / key_filename;

			njtls::credman cm2{rng, cert_filename, key_filename};
		}
		catch (const std::exception & err)
		{
			BOOST_CHECK_MESSAGE(false, err.what());
		}
	}
}

