control 'SV-270771' do
  title 'Ubuntu 24.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism. 
 
Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system with the following command: 
 
$ sudo dmesg | grep -i "execute disable" 
[    0.000000] NX (Execute Disable) protection: active 
 
If "dmesg" does not show "NX (Execute Disable) protection: active", check the cpuinfo settings with the following command:  
 
$ grep flags /proc/cpuinfo | grep -w nx | sort -u 
flags       : fpu vme de pse tsc ms nx rdtscp lm constant_tsc 
 
If "flags" does not contain the "nx" flag, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS to enable NX. 
 
If "nx" is not showing up in "/proc/cpuinfo", and the system's BIOS setup configuration permits toggling the No Execution bit, set it to "enable".)
  impact 0.5
  tag check_id: 'C-74804r1066800_chk'
  tag severity: 'medium'
  tag gid: 'V-270771'
  tag rid: 'SV-270771r1066802_rule'
  tag stig_id: 'UBTU-24-700300'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-74705r1066801_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  dmesg_nx_conf = command('dmesg | grep \'[NX|DX]*protection\'').stdout

  describe 'The no-execution bit flag' do
    it 'should be set in kernel messages' do
      expect(dmesg_nx_conf).to_not eq(''), 'dmesg does not set ExecShield'
    end
    unless dmesg_nx_conf.empty?
      it 'should be active' do
        expect(dmesg_nx_conf.match(/:\s+(\S+)$/).captures.first).to eq('active'), "dmesg does not show ExecShield set to 'active'"
      end
    end
  end
end
