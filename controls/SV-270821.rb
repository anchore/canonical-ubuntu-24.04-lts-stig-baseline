control 'SV-270821' do
  title 'Ubuntu 24.04 LTS must configure audit tools with a mode of "0755" or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information. 
 
Operating systems providing tools to interface with audit information will leverage user permissions, roles identifying the user accessing the tools, and the corresponding user rights to make decisions regarding access to audit tools. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify Ubuntu 24.04 LTS configures the audit tools to have a file permission of "0755" or less to prevent unauthorized access with the following command:  
 
$ stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules
/sbin/auditctl 755 
/sbin/aureport 755 
/sbin/ausearch 755 
/sbin/autrace 755 
/sbin/auditd 755 
/sbin/audispd 755 
/sbin/augenrules 755 
 
If any of the audit tools have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure the audit tools on Ubuntu 24.04 LTS to be protected from unauthorized access by setting the correct permissive mode using the following command: 
 
$ sudo chmod 0755 [audit_tool] 
 
Replace "[audit_tool]" with the audit tool that does not have the correct permissions.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag gid: 'V-270821'
  tag rid: 'SV-270821r1068391_rule'
  tag stig_id: 'UBTU-24-901230'
  tag fix_id: 'F-74755r1066951_fix'
  tag cci: ['CCI-001493', 'CCI-001494']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = input('audit_tools')

  failing_tools = audit_tools.select { |at| file(at).more_permissive_than?(input('audit_tool_mode')) }

  describe 'Audit executables' do
    it "should be no more permissive than '#{input('audit_tool_mode')}'" do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
