control 'SV-270693' do
  title 'Ubuntu 24.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.'
  desc %q(Display of a standardized and approved use notification before granting access to Ubuntu 24.04 LTS ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 
 
System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist. 
 
The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters: 
 
"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
 
-At any time, the USG may inspect and seize data stored on this IS. 
 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
 
Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner: 
 
"I've read (literal ampersand) consent to terms in IS user agreem't.")
  desc 'check', 'Note: If the system does not have a graphical user interface installed, this requirement is not applicable. 

Verify Ubuntu 24.04 LTS displays the Standard Mandatory DOD Notice and Consent Banner before granting access to Ubuntu 24.04 LTS via a graphical user logon with the command: 
 
$ grep ^banner-message-text /etc/gdm3/greeter.dconf-defaults 
banner-message-text="You are accessing a U.S. Government \\(USG\\) Information System \\(IS\\) that is provided for USG-authorized use only.\\s+By using this IS \\(which includes any device attached to this IS\\), you consent to the following conditions:\\s+-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct \\(PM\\), law enforcement \\(LE\\), and counterintelligence \\(CI\\) investigations.\\s+-At any time, the USG may inspect and seize data stored on this IS.\\s+-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\\s+-This IS includes security measures \\(e.g., authentication and access controls\\) to protect USG interests--not for your personal benefit or privacy.\\s+-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 
 
If the banner-message-text is missing, commented out, or does not match the Standard Mandatory DOD Notice and Consent Banner exactly, this is a finding.'
  desc 'fix', %q(Configure Ubuntu 24.04 LTS displays the Standard Mandatory DOD Notice and Consent Banner before granting access to Ubuntu 24.04 LTS via a graphical user logon.

Edit the "/etc/gdm3/greeter.dconf-defaults" file. 
 
Set the "banner-message-text" line to contain the appropriate banner message text as shown below: 
 
banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.' 
 
Update the GDM with the new configuration: 
 
$ sudo dconf update 
$ sudo systemctl restart gdm3)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag gid: 'V-270693'
  tag rid: 'SV-270693r1066568_rule'
  tag stig_id: 'UBTU-24-200660'
  tag fix_id: 'F-74627r1066567_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']
  tag 'host'

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed, this control is Not Applicable' do
      skip 'A GUI desktop is not installed, this control is Not Applicable.'
    end
  else
    describe command('grep ^banner-message-enable /etc/dconf/db/local.d/*') do
      its('stdout.strip') { should cmp 'banner-message-enable=true' }
    end
  end
end
