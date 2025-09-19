control 'SV-270726' do
  title 'Ubuntu 24.04 LTS must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces password complexity by requiring that at least one uppercase character be used with the following command: 
 
$ grep -i "ucredit" /etc/security/pwquality.conf
ucredit=-1 
 
If the "ucredit" parameter is greater than "-1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce password complexity by requiring that at least one uppercase character be used. 

Add or update the "/etc/security/pwquality.conf" file to contain the "ucredit" parameter: 
 
ucredit=-1'
  impact 0.5
  tag check_id: 'C-74759r1066665_chk'
  tag severity: 'medium'
  tag gid: 'V-270726'
  tag rid: 'SV-270726r1066667_rule'
  tag stig_id: 'UBTU-24-400260'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-74660r1066666_fix'
  tag satisfies: ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf:' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'ucredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `ucredit` set' do
      expect(value).not_to be_empty, 'ucredit is not set in pwquality.conf'
    end

    it 'only sets `ucredit` once' do
      expect(value.length).to eq(1), 'ucredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `ucredit` to a positive value' do
      expect(value.first.to_i).to cmp < 0, 'ucredit is not set to a negative value in pwquality.conf'
    end
  end
end
