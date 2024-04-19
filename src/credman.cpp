//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <njtls/credman.hpp>
#include <botan/data_src.h>
#include <filesystem>
#include <string>
#include <botan/pkcs8.h>

njtls::credman::credman(
	Botan::RandomNumberGenerator & rng,
	const std::filesystem::path & cert_filename,
	const std::filesystem::path & key_filename
)
{
	using std::string_literals::operator""s;
	if (! std::filesystem::exists(cert_filename))
		throw std::runtime_error{"ERROR: cert_filename: "s + cert_filename.string() + " does not exist!"};
	if (! std::filesystem::exists(key_filename))
		throw std::runtime_error{"ERROR: key_filename: "s + key_filename.string() + " does not exist!"};

// Load cert_filename
	Botan::DataSource_Stream cert_in{cert_filename.string()};
	njtls::credman::certificate_info cert_info;
	while (! cert_in.end_of_data())
	{
		try
		{
			cert_info.certs.push_back(Botan::X509_Certificate{cert_in});
		}
		catch (...)
		{
		}
	}
	cert_info_list.push_back(cert_info);

// Load key_filename
	Botan::DataSource_Stream key_in{key_filename.string()};
	cert_info.key.reset(Botan::PKCS8::load_key(key_in).release());
}

std::vector<Botan::Certificate_Store *> njtls::credman::trusted_certificate_authorities(
	const std::string & type,
	const std::string & context
)
{
	if (type == "tls-server")
		return {};
	std::vector<Botan::Certificate_Store *> list;
	for (const auto & store: store_list)
		list.push_back(store.get());
	return list;
}

std::vector<Botan::X509_Certificate> njtls::credman::cert_chain(
	const std::vector<std::string> & cert_key_types,
	const std::vector<Botan::AlgorithmIdentifier> & cert_sig_schs,
	const std::string & type,
	const std::string & context
)
{
	// todo: cert_sig_schs is unused.

	for (const auto & cert_info: cert_info_list)
	{
		if (
			std::find(
				cert_key_types.begin(),
				cert_key_types.end(),
				cert_info.key->algo_name()
			) == cert_key_types.end()
		)
			continue;
		if (context != "" && cert_info.certs[0].matches_dns_name(context))
			continue;
		return cert_info.certs;
	}
	return {};
} 

std::shared_ptr<Botan::Private_Key> njtls::credman::private_key_for(
	const Botan::X509_Certificate & cert,
	const std::string & type,
	const std::string & context
)
{
	for (const auto & cert_info: cert_info_list)
	{
		if (cert == cert_info.certs[0])
			return cert_info.key;
	}
	return nullptr;
}
