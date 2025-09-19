control 'SV-270725' do
  title 'Ubuntu 24.04 LTS must store only encrypted representations of passwords.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  desc 'check', 'Verify the Ubuntu operating system stores only encrypted representations of passwords with the following command:

$ grep pam_unix.so /etc/pam.d/common-password
password [success=1 default=ignore] pam_unix.so obscure sha512 shadow rounds=100000

If "sha512" is missing from the "pam_unix.so" line, or if the "rounds" is set to less than 100000, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to store encrypted representations of passwords.

Add or modify the "sha512" parameter value to the following line in "/etc/pam.d/common-password" file:

password [success=1 default=ignore] pam_unix.so obscure sha512 shadow rounds=100000'
  impact 0.5
  tag check_id: 'C-74758r1101787_chk'
  tag severity: 'medium'
  tag gid: 'V-270725'
  tag rid: 'SV-270725r1101789_rule'
  tag stig_id: 'UBTU-24-400220'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-74659r1101788_fix'
  tag 'documentable'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
  end
end
