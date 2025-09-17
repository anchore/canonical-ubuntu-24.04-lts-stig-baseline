control 'SV-270746' do
  title 'Ubuntu 24.04 LTS must disable kernel core dumps.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed with the following command: 
 
$ systemctl is-active kdump-tools.service
inactive 
 
If the "kdump-tools" service is active, ask the system administrator (SA) if the use of the service is required and documented with the information system security officer (ISSO). 
 
If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable the "kdump-tools" service with the following command: 
 
$ sudo systemctl disable kdump-tools.service
 
If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  tag check_id: 'C-74779r1101767_chk'
  tag severity: 'medium'
  tag gid: 'V-270746'
  tag rid: 'SV-270746r1101769_rule'
  tag stig_id: 'UBTU-24-600070'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag fix_id: 'F-74680r1101768_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('kdump') do
    it { should_not be_running }
    its('params.LoadState') { should cmp 'masked' }
    its('params.UnitFileState') { should cmp 'masked' }
  end
end
