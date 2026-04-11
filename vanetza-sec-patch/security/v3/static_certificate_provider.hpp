#pragma once
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/persistence.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Static certificate provider for pre-provisioned credentials
 *
 * Holds a pre-loaded Authorization Ticket (AT) and its associated private key,
 * generated offline by the C-ITS-PKI Python toolkit.  Implements the
 * CertificateProvider interface so that Vanetza's sign service can use it
 * directly in place of NaiveCertificateProvider.
 *
 * Usage:
 * \code
 *   // Load AT cert (raw COER binary from C-ITS-PKI cli.py issue-at)
 *   auto at_cert = vanetza::security::v3::load_certificate_from_file("at.cert");
 *
 *   // Build PrivateKey from the 32-byte raw scalar produced by
 *   // tools/export_vanetza_key.py (convert from PEM PKCS#8)
 *   vanetza::security::PrivateKey at_key;
 *   at_key.type = vanetza::security::KeyType::NistP256;
 *   // Populate at_key.key with the 32-byte scalar, e.g. via load_private_key_from_file
 *
 *   auto provider = std::make_shared<vanetza::security::v3::StaticCertificateProvider>(
 *       at_cert, at_key);
 *
 *   // Store the AA certificate in the provider's cache for chain building
 *   auto aa_cert = vanetza::security::v3::load_certificate_from_file("aa.cert");
 *   provider->cache().store(aa_cert);
 * \endcode
 *
 * \note The CertificateCache method is store(), not insert() — the Integration
 *       Guide PDF contains a typo on that point.
 */
class StaticCertificateProvider : public BaseCertificateProvider
{
public:
    /**
     * \brief Construct from a pre-loaded AT certificate and its private key
     *
     * \param authorization_ticket  COER-decoded AT certificate (from cli.py issue-at)
     * \param ticket_key            Private key matching the AT's public key.
     *                              Must be a 32-byte raw P-256 scalar loaded into
     *                              PrivateKey::key (produced by tools/export_vanetza_key.py).
     */
    StaticCertificateProvider(const Certificate& authorization_ticket, const PrivateKey& ticket_key);

    /**
     * \brief Get the Authorization Ticket for use in outgoing message headers
     * \return pre-loaded Authorization Ticket certificate
     */
    const Certificate& own_certificate() override;

    /**
     * \brief Get the private key associated with the Authorization Ticket
     * \return private key for ECDSA signing
     */
    const PrivateKey& own_private_key() override;

private:
    Certificate m_authorization_ticket;
    PrivateKey  m_authorization_ticket_key;
};

} // namespace v3
} // namespace security
} // namespace vanetza
