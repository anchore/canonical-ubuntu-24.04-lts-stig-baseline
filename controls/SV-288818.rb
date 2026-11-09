control 'SV-288818' do
  title 'Ubuntu 24.04 LTS must generate audit records for successful/unsuccessful uses of the useradd command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify an audit event is generated for any successful/unsuccessful use of the "useradd" command with the following command: 
 
$ sudo auditctl -l | grep -w useradd
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-useradd 
 
If the command does not return a line that matches the example or the line is commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "useradd" command.  
 
Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file: 
 
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-useradd 
   
To reload the rules file, issue the following command: 
 
$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-93507r1261477_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag gid: 'V-288818'
  tag rid: 'SV-288818r1261479_rule'
  tag stig_id: 'UBTU-24-900315'
  tag fix_id: 'F-93412r1261478_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  describe 'TODO' do
    skip 'Automated test for SV-288818 not yet implemented'
  end
end
