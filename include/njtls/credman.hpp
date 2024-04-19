//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#ifndef __njtls_credman_hpp__
#define __njtls_credman_hpp__

#include <memory>
#include <botan/x509cert.h>
#include <botan/credentials_manager.h>
#include <botan/rng.h>
#include <vector>
#include <string>
#include <filesystem>

namespace njtls
{

class credman: virtual public Botan::Credentials_Manager
{
public:
	class certificate_info
	{
	public:
		std::vector<Botan::X509_Certificate> certs;
		std::shared_ptr<Botan::Private_Key> key;
	};
protected:
	std::vector<njtls::credman::certificate_info> cert_info_list;
	std::vector<std::shared_ptr<Botan::Certificate_Store>> store_list;
public:
	virtual ~credman() = default;
public:
	credman() = default;
	credman(
		Botan::RandomNumberGenerator & rng,
		const std::filesystem::path & cert_filename,
		const std::filesystem::path & key_filename
	);
public:
	std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
		const std::string & type,
		const std::string & context
	) override;
public:
	std::vector<Botan::X509_Certificate> cert_chain(
		const std::vector<std::string> & cert_key_types,
		const std::vector<Botan::AlgorithmIdentifier> & cert_sig_schs,
		const std::string & type,
		const std::string & context
	) override;
public:
	std::shared_ptr<Botan::Private_Key> private_key_for(
		const Botan::X509_Certificate & cert,
		const std::string & type,
		const std::string & context
	) override;
public:
	/*
	// todo: unimplemented
	std::shared_ptr<Botan::Private_Key> private_key_for(
		const Botan::Public_Key & raw_public_key,
		const std::string & type,
		const std::string & context
	) override
	{
		return {};
	}
	*/
};	// class credman

}	// namespace njtls

#endif	// __njtls_credman_hpp__

