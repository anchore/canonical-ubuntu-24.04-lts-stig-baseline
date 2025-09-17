control 'SV-270774' do
  title 'Ubuntu 24.04 LTS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Verify the version of Ubuntu 24.04 LTS is vendor supported with the following command:

$ grep DISTRIB_DESCRIPTION /etc/lsb-release 
DISTRIB_DESCRIPTION="Ubuntu 24.04.1 LTS"

If the installed version of Ubuntu 24.04 LTS is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of Ubuntu 24.04 LTS.'
  impact 0.5
  tag check_id: 'C-74807r1066809_chk'
  tag severity: 'medium'
  tag gid: 'V-270774'
  tag rid: 'SV-270774r1066811_rule'
  tag stig_id: 'UBTU-24-700400'
  tag gtitle: 'SRG-OS-000439-GPOS-00195'
  tag fix_id: 'F-74708r1066810_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']

  describe file('/etc/lsb-release') do
    it { should exist }
    it { should include 'LTS' }
  end
end
