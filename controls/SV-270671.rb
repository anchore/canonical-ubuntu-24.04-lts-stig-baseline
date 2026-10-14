control 'SV-270671' do
  title 'Ubuntu 24.04 LTS SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the SSH client is configured to only use MACs employing FIPS 140-3 approved algorithms with the following command:

$ sudo grep -ir macs /etc/ssh/ssh_config*
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If any MACs other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" are listed, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu 24.04 LTS SSH client to use only MACs employing FIPS 140-3 approved algorithms by updating the "/etc/ssh/ssh_config" file with the following line:

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

Restart the "ssh" service for changes to take effect:

$ sudo systemctl restart ssh'
  impact 0.5
  tag check_id: 'C-74704r1155228_chk'
  tag severity: 'medium'
  tag gid: 'V-270671'
  tag rid: 'SV-270671r1155244_rule'
  tag stig_id: 'UBTU-24-100860'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-74605r1067117_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  # This is the SSH client requirement, so it applies wherever the client is installed.
  only_if('Control not applicable - SSH client is not installed within containerized Ubuntu', impact: 0.0) {
    !virtualization.container_system? || package('openssh-client').installed?
  }

  approved_macs = input('approved_openssh_server_conf')['macs']
  # DISA: a finding if any MACs other than the approved ones are listed (order is not required).
  meets_rule = ->(value) { !value.empty? && (value.split(',') - approved_macs.split(',')).empty? }

  # DISA greps the client config (/etc/ssh/ssh_config*), so read the main file and the
  # ssh_config.d drop-ins it includes. Comment lines are skipped; with none left the client uses its defaults.
  macs_lines = command("grep -iHs -E '^[[:space:]]*macs([[:space:]]|=)' /etc/ssh/ssh_config /etc/ssh/ssh_config.d/*.conf").stdout.lines.map(&:strip)
  # Drop the "file:" prefix and keyword, plus a trailing comment and quotes, which ssh also ignores.
  macs_values = macs_lines.map { |l| l.sub(/\A.*?:(?=[[:space:]]*macs[[:space:]=])/i, '').strip.sub(/^macs[[:space:]=]+/i, '').sub(/[[:space:]]+#.*\z/, '').delete(%q("')).strip }.uniq

  describe 'OpenSSH client MACs in /etc/ssh/ssh_config and /etc/ssh/ssh_config.d/*.conf' do
    it 'are set, not commented out' do
      expect(macs_values).not_to be_empty, 'No uncommented MACs line found'
    end
    it 'list only approved algorithms' do
      bad = macs_values.reject { |value| meets_rule.call(value) }
      expect(bad).to be_empty, "OpenSSH client MACs:\n\t#{bad.join("\n\t")}\ndo not meet the approved value:\n\t#{approved_macs}"
    end
  end
end
