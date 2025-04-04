control 'SV-270735' do
  title 'Ubuntu 24.04 LTS, for PKI-based authentication, SSSD must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.  
  
A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.  
  
When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.  
  
This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor. 

Ensure the pam service is listed under [sssd] with the following command:

$ sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf
[sssd]
services = nss,pam,ssh

If "pam" is not listed in services, this is a finding.

Additionally, ensure the pam service is set to use pam for smart card authentication in the [pam] section of /etc/sssd/sssd.conf with the following command:

$ sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf
[pam]
pam_cert_auth = True

If "pam_cert_auth = True" is not returned, this is a finding.

Ensure "ca" is enabled in "certificate_verification" with the following command: 
  
$ sudo grep certificate_verification /etc/sssd/sssd.conf
certificate_verification = ca_cert,ocsp
 
If "certificate_verification" is not set to "ca" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS, for PKI-based authentication, to validate certificates by constructing a certification path to an accepted trust anchor. 
 
Add or update the /etc/sssd/sssd.conf so that the following entries are in the correct sections of the file: 
 
$ sudo vi /etc/sssd/sssd.conf

[sssd]
services = nss,pam,ssh
config_file_version = 2

[pam]
pam_cert_auth = True

[domain/example.com]
ldap_user_certificate = usercertificate;binary
certificate_verification = ca_cert,ocsp
ca_cert = /etc/ssl/certs/ca-certificates.crt'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000384-GPOS-00167', 'SRG-OS-000775-GPOS-00230']
  tag gid: 'V-270735'
  tag rid: 'SV-270735r1066694_rule'
  tag stig_id: 'UBTU-24-400360'
  tag fix_id: 'F-74669r1066693_fix'
  tag cci: ['CCI-000185', 'CCI-001991', 'CCI-004909']
  tag nist: ['IA-5 (2) (a)', 'IA-5 (2) (b) (1)', 'IA-5 (2) (d)', 'SC-17 b']
  tag 'host'
  tag 'container'

  only_if('If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.', impact: 0.0) {
    !input('smart_card_enabled')
  }

  root_ca_file = input('root_ca_file')
  describe file(root_ca_file) do
    it { should exist }
  end

  describe 'Ensure the RootCA is a DoD-issued certificate with a valid date' do
    if file(root_ca_file).exist?
      subject { x509_certificate(root_ca_file) }
      it 'has the correct issuer_dn' do
        expect(subject.issuer_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 3')
      end
      it 'has the correct subject_dn' do
        expect(subject.subject_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 3')
      end
      it 'is valid' do
        expect(subject.validity_in_days).to be > 0
      end
    end
  end
end
