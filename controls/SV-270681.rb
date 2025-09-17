control 'SV-270681' do
  title 'Ubuntu 24.04 LTS must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk, and make remote user access management difficult at best. 
 
Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Automated monitoring of remote access sessions allows organizations to detect cyberattacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that Ubuntu 24.04 LTS monitors all remote access methods with the following command: 
 
$  grep -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.* 
/etc/rsyslog.d/50-default.conf:auth,authpriv.*                        /var/log/auth.log 
/etc/rsyslog.d/50-default.conf:daemon.*                        /var/log/messages 
 
If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged in at least one of the config files, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to monitor all remote access methods by adding the following lines to the "/etc/rsyslog.d/50-default.conf" file: 
 
auth.*,authpriv.* /var/log/secure 
daemon.* /var/log/messages 
 
For the changes to take effect, restart the "rsyslog" service with the following command: 
 
$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-74714r1066530_chk'
  tag severity: 'medium'
  tag gid: 'V-270681'
  tag rid: 'SV-270681r1066532_rule'
  tag stig_id: 'UBTU-24-200090'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-74615r1066531_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable; remote access not configured within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  rsyslog = file('/etc/rsyslog.conf')

  describe rsyslog do
    it { should exist }
  end

  if rsyslog.exist?

    auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
    authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
    daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

    rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf')

    describe 'Logged remote access methods' do
      it 'should include auth.*' do
        expect(rsyslog_conf.stdout).to match(auth_pattern), 'auth.* not configured for logging'
      end
      it 'should include authpriv.*' do
        expect(rsyslog_conf.stdout).to match(authpriv_pattern), 'authpriv.* not configured for logging'
      end
      it 'should include daemon.*' do
        expect(rsyslog_conf.stdout).to match(daemon_pattern), 'daemon.* not configured for logging'
      end
    end
  end
end
