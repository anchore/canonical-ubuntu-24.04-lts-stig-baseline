control 'SV-270718' do
  title 'Ubuntu 24.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, devices such as flash drives, external storage, and printers.'
  desc 'check', 'Verify that Ubuntu 24.04 LTS disables ability to load the USB storage kernel module with the following command:

$ sudo grep usb-storage /etc/modprobe.d/* | grep "/bin/true" 
/etc/modprobe.d/DISASTIG.conf:install usb-storage /bin/true

If the command does not return any output, or the line is commented out, this is a finding.

Verify Ubuntu 24.04 LTS disables the ability to use USB mass storage device.

$ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"
/etc/modprobe.d/DISASTIG.conf:blacklist usb-storage

If the command does not return any output, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to disable using the USB storage kernel module with the following command: 

$ sudo su -c "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"

Configure Ubuntu 24.04 LTS to disable the ability to use USB mass storage devices with the following command:

$ sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"'
  impact 0.5
  tag check_id: 'C-74751r1067127_chk'
  tag severity: 'medium'
  tag gid: 'V-270718'
  tag rid: 'SV-270718r1067128_rule'
  tag stig_id: 'UBTU-24-300039'
  tag gtitle: 'SRG-OS-000690-GPOS-00140'
  tag fix_id: 'F-74652r1066642_fix'
  tag 'documentable'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command('grep usb-storage /etc/modprobe.d/* | grep "/bin/true"') do
      its('stdout') { should_not be_empty }
    end

    describe command('grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"') do
      its('stdout') { should_not be_empty }
    end
  end
end
