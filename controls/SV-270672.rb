control 'SV-270672' do
  title 'Ubuntu 24.04 LTS must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.  
  
DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the "opensc-pcks11" package is installed on the system with the following command: 
 
$ dpkg -l | grep opensc-pkcs11 
ii  opensc-pkcs11:amd64        0.25.0~rc1-1build2    amd64        Smart card utilities with support for PKCS#15 compatible cards 
 
If the "opensc-pcks11" package is not installed, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to accept PIV credentials. 
 
Install the "opensc-pkcs11" package using the following command: 
 
$ sudo apt install -y opensc-pkcs11'
  impact 0.5
  tag check_id: 'C-74705r1066503_chk'
  tag severity: 'medium'
  tag gid: 'V-270672'
  tag rid: 'SV-270672r1067161_rule'
  tag stig_id: 'UBTU-24-100900'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag fix_id: 'F-74606r1067160_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953']
  tag nist: ['IA-2 (11)', 'IA-2 (12)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('smart_card_enabled')
    describe package('opensc') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable.'
    end
  end
end
