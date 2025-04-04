control 'SV-270707' do
  title 'Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.   
  
When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" with the following command: 
 
$ sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* 
 
If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "NOPASSWD" or "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-270707'
  tag rid: 'SV-270707r1066610_rule'
  tag stig_id: 'UBTU-24-300021'
  tag fix_id: 'F-74641r1066609_fix'
  tag cci: ['CCI-002038', 'CCI-000366']
  tag nist: ['IA-11', 'CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  describe sudoers(input('sudoers_config_files')) do
    its('settings.Defaults') { should_not include '!authenticate' }
  end
end
