control 'SV-270756' do
  title 'Ubuntu 24.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization. 
 
Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

The /var/log/btmp, /var/log/wtmp, and /var/log/lastlog files have group write and global read permissions to allow for the lastlog function to perform. Limiting the permissions beyond this configuration will result in the failure of functions that rely on the lastlog database.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS has all system log files under the /var/log directory with a permission set to "640" or less permissive with the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;

If the command displays any output, this is a finding.)
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to set permissions of all log files under the /var/log directory to "640" or more restricted by using the following command:

Note: The btmp, wtmp, and lastlog files are excluded. Refer to the Discussion for details.

$ sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec chmod 640 '{}' \;)
  impact 0.5
  tag check_id: 'C-74789r1066755_chk'
  tag severity: 'medium'
  tag gid: 'V-270756'
  tag rid: 'SV-270756r1066757_rule'
  tag stig_id: 'UBTU-24-700010'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-74690r1066756_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    it { should_not be_more_permissive_than('0755') }
  end
end
