control 'SV-270775' do
  title 'Ubuntu 24.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.  
  
Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files have a mode of "0640" or less permissive with the following command: 
 
$ sudo ls -al /etc/audit/ /etc/audit/rules.d/
/etc/audit/: 
 
-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf 
 -rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules 
-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules 
 
drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d 
 
/etc/audit/rules.d/: 

 -rw-r----- 1 root root 244 Dec 27 09:56 audit.rules 
-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules 
 
If /etc/audit/audit.rule, /etc/audit/rules.d/*, or /etc/audit/auditd.conf files have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure /etc/audit/audit.rules, /etc/audit/rules.d/*, and /etc/audit/auditd.conf files to have a mode of "0640" by using the following command: 
 
$ sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag gid: 'V-270775'
  tag rid: 'SV-270775r1068369_rule'
  tag stig_id: 'UBTU-24-900040'
  tag fix_id: 'F-74709r1066813_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  rules_files = bash('ls -d /etc/audit/rules.d/*.rules').stdout.strip.split.append('/etc/audit/auditd.conf').append('/etc/audit/audit.rules')
  failing_files = rules_files.select { |rf| file(rf).more_permissive_than?(input('audit_conf_mode')) }
  describe 'Audit configuration files' do
    it "should be no more permissive than '#{input('audit_conf_mode')}'" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
