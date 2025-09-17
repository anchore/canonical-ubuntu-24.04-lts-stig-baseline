control 'SV-270807' do
  title 'Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all modifications that affect "/etc/sudoers" with the following command: 
 
$ sudo auditctl -l | grep sudoers
-w /etc/sudoers -p wa -k privilege_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for all modifications that affect "/etc/sudoers".  

Add or update the following rule to "/etc/audit/rules.d/stig.rules": 

-w /etc/sudoers -p wa -k privilege_modification 

To reload the rules file, issue the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74840r1066908_chk'
  tag severity: 'medium'
  tag gid: 'V-270807'
  tag rid: 'SV-270807r1066910_rule'
  tag stig_id: 'UBTU-24-900510'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-74741r1066909_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/etc/sudoers'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
