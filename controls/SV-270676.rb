control 'SV-270676' do
  title 'Ubuntu 24.04 LTS must initiate session audits at system startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Verify that Ubuntu 24.04 LTS enables auditing at system startup in grub with the following command 
 
$ sudo grep "^\\s*linux" /boot/grub/grub.cfg 
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro audit=1 quiet splash $vt_handoff
linux   /vmlinuz-6.8.0-31-generic root=UUID=c92a542f-aee4-4af9-94b2-203624ccb8e3 ro recovery nomodeset dis_ucode_ldr audit=1
 
If any linux lines do not contain "audit=1", this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to produce audit records at system startup.  
 
Edit the "/etc/default/grub" file and add "audit=1" to the "GRUB_CMDLINE_LINUX" option so that the line looks like this:

GRUB_CMDLINE_LINUX="audit=1"
 
To update the grub config file, run: 
 
$ sudo update-grub'
  impact 0.5
  tag check_id: 'C-74709r1066515_chk'
  tag severity: 'medium'
  tag gid: 'V-270676'
  tag rid: 'SV-270676r1068360_rule'
  tag stig_id: 'UBTU-24-102010'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-74610r1066516_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /audit\s*=\s*1/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
