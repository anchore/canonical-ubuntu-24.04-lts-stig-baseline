control 'SV-270702' do
  title 'Ubuntu 24.04 LTS must have system commands owned by root or a system account.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu 24.04 LTS with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories are owned by root, or a required system account, with the following command: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
 
If any system commands are returned and not owned by a required system account, this is a finding.)
  desc 'fix', 'Configure the system commands and their respective parent directories to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any system command file not owned by "root" or a required system account: 
 
$ sudo chown root [FILE]'
  impact 0.5
  tag check_id: 'C-74735r1066593_chk'
  tag severity: 'medium'
  tag gid: 'V-270702'
  tag rid: 'SV-270702r1066595_rule'
  tag stig_id: 'UBTU-24-300012'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-74636r1066594_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} ! -user root -exec ls -d {} \\;").stdout.split("\n")

  describe 'System commands' do
    it 'should be owned by root' do
      expect(failing_files).to be_empty, "Files not owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
