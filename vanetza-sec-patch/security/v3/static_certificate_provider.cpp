#include <vanetza/security/v3/static_certificate_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

StaticCertificateProvider::StaticCertificateProvider(
    const Certificate& authorization_ticket,
    const PrivateKey& ticket_key) :
    m_authorization_ticket(authorization_ticket),
    m_authorization_ticket_key(ticket_key)
{
}

const Certificate& StaticCertificateProvider::own_certificate()
{
    return m_authorization_ticket;
}

const PrivateKey& StaticCertificateProvider::own_private_key()
{
    return m_authorization_ticket_key;
}

} // namespace v3
} // namespace security
} // namespace vanetza
