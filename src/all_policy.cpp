//
// Copyright (c) 2024 Fas Xmut (fasxmut at protonmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <njtls/all_policy.hpp>
#include <fstream>
#include <string>

std::vector<std::string> njtls::all_policy::allowed_ciphers() const
{
	return
		{
			"AES-256/OCB(12)",
			"AES-128/OCB(12)",
			"AES-256/GCM",
			"AES-128/GCM",
			"AES-256/CCM",
			"AES-128/CCM",
			"AES-256/CCM(8)",
			"AES-128/CCM(8)",
			"AES-256",
			"AES-128",
			"Camellia-256/GCM",
			"Camellia-128/GCM",
			"Camellia-256",
			"Camellia-128",
			"ARIA-256/GCM",
			"ARIA-128/GCM",
			"ChaCha20Poly1305",
			"SEED",
			"3DES"
		};
}

std::vector<std::string> njtls::all_policy::allowed_key_exchange_methods() const
{
	return
		{
			"SRP_SHA",
			"ECDHE_PSK",
			"DHE_PSK",
			"PSK",
			"CECPQ1",
			"ECDH",
			"DH",
			"RSA"
		};
}

std::vector<std::string> njtls::all_policy::allowed_signature_methods() const
{
	return
		{
			"ECDSA",
			"RSA",
			"DSA",
			"IMPLICIT"
		};
}

inline std::unique_ptr<Botan::TLS::Policy> njtls::all_policy::load(
	const std::string & policy_type
)
{
	if (policy_type == "" || policy_type == "default")
		return std::make_unique<Botan::TLS::Policy>();

	if (policy_type == "suiteb128")
		return std::make_unique<Botan::TLS::NSA_Suite_B_128>();

	if (policy_type == "suiteb" || policy_type == "suiteb192")
		return std::make_unique<Botan::TLS::NSA_Suite_B_192>();

	if (policy_type == "bsi")
		return std::make_unique<Botan::TLS::BSI_TR_02102_2>();

	if (policy_type == "datagram")
		return std::make_unique<Botan::TLS::Datagram_Policy>();

	if (policy_type == "strict")
		return std::make_unique<Botan::TLS::Strict_Policy>();

	if (policy_type == "all")
		return std::make_unique<std::decay_t<decltype(*this)>>();

	std::ifstream policy_file{policy_type};
	if (policy_file.is_open())
		return std::make_unique<Botan::TLS::Text_Policy>(policy_file);

	using std::string_literals::operator""s;
	throw std::runtime_error{"ERROR, njtls::all_policy::load: "s + policy_type + "  policy is unknown."};
}

