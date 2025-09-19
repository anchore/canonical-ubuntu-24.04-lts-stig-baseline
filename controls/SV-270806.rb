control 'SV-270806' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module syscall.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify Ubuntu 24.04 LTS generates an audit record for any successful/unsuccessful attempts to use the "delete_module" syscall with the following command: 
 
$ sudo auditctl -l | grep -w delete_module
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Notes: 
- For 32-bit architectures, only the 32-bit specific output lines from the commands are required. 
- The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "delete_module" syscall.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
  
Note: For 32-bit architectures, only the 32-bit specific entries are required.  
  
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-74839r1068385_chk'
  tag severity: 'medium'
  tag gid: 'V-270806'
  tag rid: 'SV-270806r1068386_rule'
  tag stig_id: 'UBTU-24-900350'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-74740r1066906_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_syscalls = ['delete_module']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        if os.arch.match(/64/)
          expect(audit_rule.arch.uniq).to include('b32', 'b64')
        else
          expect(audit_rule.arch.uniq).to cmp 'b32'
        end
        expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
