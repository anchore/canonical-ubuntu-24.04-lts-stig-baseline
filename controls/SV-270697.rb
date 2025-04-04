control 'SV-270697' do
  title 'Ubuntu 24.04 LTS library files must be owned by root.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" are owned by root with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \; 
 
If any systemwide library file is returned, this is a finding.)
  desc 'fix', "Configure the system library files to be protected from unauthorized access. Run the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \\;"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-270697'
  tag rid: 'SV-270697r1066580_rule'
  tag stig_id: 'UBTU-24-300007'
  tag fix_id: 'F-74631r1066579_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_libraries').join(' ')} ! -user root -exec ls -d {} \\;").stdout.split("\n")

  describe 'System libraries' do
    it 'should be owned by root' do
      expect(failing_files).to be_empty, "Files not owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
