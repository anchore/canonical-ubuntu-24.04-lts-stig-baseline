control 'SV-270669' do
  title 'Ubuntu 24.04 LTS SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list.'
  desc 'check', 'Verify that the SSH daemon is configured to use only FIPS-validated key exchange algorithms with the following command:

$ sudo grep -ir kexalgorithms /etc/ssh/sshd_config*
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/ssh/sshd_config":

KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

Restart the "sshd" service for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  tag check_id: 'C-74702r1134803_chk'
  tag severity: 'medium'
  tag gid: 'V-270669'
  tag rid: 'SV-270669r1134804_rule'
  tag stig_id: 'UBTU-24-100840'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-74603r1066495_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !virtualization.container_system? || package('openssh-server').installed?
  }

  expected_kex = input('expected_kex')
  # DISA: a finding if KexAlgorithms lists any algorithm other than the approved ones (order is not required).
  meets_rule = ->(value) { !value.empty? && (value.split(',') - expected_kex).empty? }

  # DISA greps every sshd config file (/etc/ssh/sshd_config*), so read the main file and the
  # sshd_config.d drop-ins it includes, not only the main file. Comment lines are skipped.
  kex_lines = command("grep -iHs -E '^[[:space:]]*kexalgorithms([[:space:]]|=)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf").stdout.lines.map(&:strip)
  # Drop the "file:" prefix and keyword, plus a trailing comment and quotes, which sshd also ignores.
  kex_values = kex_lines.map { |l| l.sub(/\A.*?:(?=[[:space:]]*kexalgorithms[[:space:]=])/i, '').strip.sub(/^kexalgorithms[[:space:]=]+/i, '').sub(/[[:space:]]+#.*\z/, '').delete(%q("')).strip }.uniq

  describe 'SSHD KexAlgorithms in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf' do
    it 'are set, not commented out' do
      expect(kex_values).not_to be_empty, 'No uncommented KexAlgorithms line found'
    end
    it 'list only approved algorithms' do
      bad = kex_values.reject { |value| meets_rule.call(value) }
      expect(bad).to be_empty, "SSHD KexAlgorithms:\n\t#{bad.join("\n\t")}\ndo not meet the approved value:\n\t#{expected_kex.join(',')}"
    end
  end

  # sshd -T reports the effective value but exits non-zero in images without /run/sshd, so use it only when it runs.
  sshd_t = command('/usr/sbin/sshd -T')
  if sshd_t.exit_status.zero?
    effective_kex = sshd_t.stdout.lines.map(&:split).find { |k, _| k == 'kexalgorithms' }&.last.to_s
    describe 'Effective SSHD KexAlgorithms (sshd -T)' do
      it 'list only approved algorithms' do
        expect(meets_rule.call(effective_kex)).to be(true),"Effective KexAlgorithms:\n\t#{effective_kex}\ndo not meet the approved value:\n\t#{expected_kex.join(',')}"
      end
    end
  end
end
