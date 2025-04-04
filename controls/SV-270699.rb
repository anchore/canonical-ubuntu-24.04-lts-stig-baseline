control 'SV-270699' do
  title 'Ubuntu 24.04 LTS library files must be group-owned by root or a system account.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide library files contained in the directories "/lib", "/lib64", and "/usr/lib" are group-owned by root, or a required system account, with the following command: 
 
$ sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \; 
 
If any systemwide shared library file is returned and is not group-owned by a required system account, this is a finding.)
  desc 'fix', 'Configure the system library files to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account: 
 
$ sudo chgrp root [FILE]'
  impact 0.5
  tag check_id: 'C-74732r1066584_chk'
  tag severity: 'medium'
  tag gid: 'V-270699'
  tag rid: 'SV-270699r1066586_rule'
  tag stig_id: 'UBTU-24-300009'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-74633r1066585_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
