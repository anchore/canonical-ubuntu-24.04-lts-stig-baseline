control 'SV-270764' do
  title 'Ubuntu 24.04 LTS must configure the files used by the system journal to be owned by "root"'
  desc "Only authorized personnel are to be made aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify Ubuntu 24.04 LTS or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /run/log/journal and /var/log/journal files are owned by "root" with the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \\; 
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system.journal root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000@0005f97cd4a8c9b5-f088232c3718485a.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cd2a1e0a7-d58b848af46813a4.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cb900e501-55ea053b7f75ae1c.journal~ root
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000.journal root

If any output returned is not owned by "root", this is a finding.'
  desc 'fix', 'Configure the system to set the appropriate ownership to the files used by the systemd journal:

$ sudo nano /usr/lib/tmpfiles.d/systemd.conf

Edit the following lines of the configuration file:

Z /run/log/journal/%m ~2640 root systemd-journal - -
z /var/log/journal/%m 2640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Note: The system must be restarted for these settings to take effect.'
  impact 0.5
  tag check_id: 'C-74797r1066779_chk'
  tag severity: 'medium'
  tag gid: 'V-270764'
  tag rid: 'SV-270764r1066781_rule'
  tag stig_id: 'UBTU-24-700090'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-74698r1066780_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
