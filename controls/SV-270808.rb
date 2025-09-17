control 'SV-270808' do
  title 'Ubuntu 24.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates audit records for all modifications that affect "/etc/sudoers.d" directory with the following command:  
 
$ sudo auditctl -l | grep sudoers.d
-w /etc/sudoers.d -p wa -k privilege_modification 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to generate audit records for all modifications that affect "/etc/sudoers.d" directory.  

Add or update the following rule to "/etc/audit/rules.d/stig.rules": 

-w /etc/sudoers.d -p wa -k privilege_modification 

To reload the rules file, issue the following command: 

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74841r1066911_chk'
  tag severity: 'medium'
  tag gid: 'V-270808'
  tag rid: 'SV-270808r1067100_rule'
  tag stig_id: 'UBTU-24-900520'
  tag gtitle: 'SRG-OS-000466-GPOS-00210'
  tag fix_id: 'F-74742r1066912_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_command = '/etc/sudoers.d'

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
