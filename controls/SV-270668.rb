control 'SV-270668' do
  title 'Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the SSH daemon is configured to only use MACs that employ FIPS 140-3 approved ciphers with the following command:

$ grep -irs macs /etc/ssh/sshd_config*
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If any algorithms other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" are listed, the returned line is commented out, or if conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to allow the SSH daemon to only use MACs that employ FIPS 140-3 approved ciphers.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

Restart the "sshd" service for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000424-GPOS-00188']
  tag gid: 'V-270668'
  tag rid: 'SV-270668r1067110_rule'
  tag stig_id: 'UBTU-24-100830'
  tag fix_id: 'F-74602r1067109_fix'
  tag cci: ['CCI-001453', 'CCI-002421', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized Ubuntu', impact: 0.0) {
    !virtualization.container_system? || file('/etc/ssh/sshd_config').exist?
  }

  approved_macs = input('approved_openssh_server_conf')['macs']
  # DISA: a finding if any algorithm other than the approved ones is listed (order is not required).
  meets_rule = ->(value) { !value.empty? && (value.split(',') - approved_macs.split(',')).empty? }

  # DISA greps every sshd config file (/etc/ssh/sshd_config*), so read the main file and the
  # sshd_config.d drop-ins it includes, not only the main file. Comment lines are skipped.
  macs_lines = command("grep -iHs -E '^[[:space:]]*macs([[:space:]]|=)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf").stdout.lines.map(&:strip)
  # Drop the "file:" prefix and keyword, plus a trailing comment and quotes, which sshd also ignores.
  macs_values = macs_lines.map { |l| l.sub(/\A.*?:(?=[[:space:]]*macs[[:space:]=])/i, '').strip.sub(/^macs[[:space:]=]+/i, '').sub(/[[:space:]]+#.*\z/, '').delete(%q("')).strip }.uniq

  describe 'OpenSSH server MACs in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf' do
    it 'are set, not commented out' do
      expect(macs_values).not_to be_empty, 'No uncommented MACs line found'
    end
    it 'have no conflicting values' do
      expect(macs_values.length).to be <= 1, "Conflicting MACs lines:\n\t#{macs_lines.join("\n\t")}"
    end
    it 'list only approved algorithms' do
      bad = macs_values.reject { |value| meets_rule.call(value) }
      expect(bad).to be_empty, "OpenSSH server MACs:\n\t#{bad.join("\n\t")}\ndo not meet the approved value:\n\t#{approved_macs}"
    end
  end

  # sshd -T reports the effective value but exits non-zero in images without /run/sshd, so use it only when it runs.
  sshd_t = command('/usr/sbin/sshd -T')
  if sshd_t.exit_status.zero?
    effective_macs = sshd_t.stdout.lines.map(&:split).find { |k, _| k == 'macs' }&.last.to_s
    describe 'Effective OpenSSH server MACs (sshd -T)' do
      it 'list only approved algorithms' do
        expect(meets_rule.call(effective_macs)).to be(true), "Effective MACs:\n\t#{effective_macs}\ndo not meet the approved value:\n\t#{approved_macs}"
      end
    end
  end
end
