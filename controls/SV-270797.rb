control 'SV-270797' do
  title 'Ubuntu 24.04 LTS must generate audit records for the use and modification of the lastlog file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record when successful/unsuccessful modifications to the "lastlog" file occur with the following command:  
 
$ sudo auditctl -l | grep lastlog
-w /var/log/lastlog -p wa -k logins 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "lastlog" file.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-w /var/log/lastlog -p wa -k logins 
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74830r1066878_chk'
  tag severity: 'medium'
  tag gid: 'V-270797'
  tag rid: 'SV-270797r1066880_rule'
  tag stig_id: 'UBTU-24-900260'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74731r1066879_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/var/log/lastlog'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
