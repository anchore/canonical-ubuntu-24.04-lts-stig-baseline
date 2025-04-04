control 'SV-270710' do
  title 'Ubuntu 24.04 LTS must display the date and time of the last successful account logon upon logon.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last occurred with the following command: 
 
$ grep pam_lastlog /etc/pam.d/login 
session     required      pam_lastlog.so showfailed 
 
If the line containing "pam_lastlog" is not set to "required", or the "silent" option is present, or the line is commented out, or the line is missing , this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/login".  
 
Add the following line to the top of "/etc/pam.d/login": 
 
session     required      pam_lastlog.so showfailed'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-270710'
  tag rid: 'SV-270710r1066619_rule'
  tag stig_id: 'UBTU-24-300024'
  tag fix_id: 'F-74644r1066618_fix'
  tag cci: ['CCI-000366', 'CCI-000052']
  tag nist: ['CM-6 b', 'AC-9']
  tag 'host'
  tag 'container'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command('grep pam_lastlog /etc/pam.d/login') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*session\s+required\s+pam_lastlog.so/) }
      its('stdout.strip') { should_not match(/^\s*session\s+required\s+pam_lastlog.so[\s\w\d\=]+.*silent/) }
    end
  end
end
