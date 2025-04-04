control 'SV-270705' do
  title 'Ubuntu 24.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.'
  desc 'check', 'Verify that Ubuntu 24.04 LTS uses "pwquality" to enforce the password complexity rules.  
 
Verify the pwquality module is being enforced by Ubuntu 24.04 LTS with the following command: 
 
$ grep -i enforcing /etc/security/pwquality.conf
enforcing = 1 
 
If the value of "enforcing" is not "1", or the line is commented out, this is a finding. 
 
Check for the use of "pwquality" with the following command: 
 
$ cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality
password requisite pam_pwquality.so retry=3 
 
If the value of "retry" is set to "0" or is greater than "3", or if a line is not returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to use "pwquality" to enforce password complexity rules. 
 
Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value): 
 
enforcing = 1 
 
Add the following line to "/etc/pam.d/common-password" (or modify the line to have the required value): 
 
password requisite pam_pwquality.so retry=3 
 
Note: Ensure the value of "retry" is between "1" and "3".'
  impact 0.5
  tag check_id: 'C-74738r1066602_chk'
  tag severity: 'medium'
  tag gid: 'V-270705'
  tag rid: 'SV-270705r1066604_rule'
  tag stig_id: 'UBTU-24-300016'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-74639r1066603_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe package('libpam-pwquality') do
      it { should be_installed }
    end

    describe parse_config_file('/etc/security/pwquality.conf') do
      its('enforcing') { should cmp 1 }
    end

    describe file('/etc/pam.d/common-password') do
      its('content') { should match '^password\s+requisite\s+pam_pwquality.so\s+retry=3$' }
    end
  end
end
