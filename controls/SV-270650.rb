control 'SV-270650' do
  title 'Ubuntu 24.04 LTS must configure AIDE to perform file integrity checking on the file system.'
  desc 'Without verification, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to Ubuntu 24.04 LTS performing security function verification/testing and/or systems and environments that require this functionality.'
  desc 'check', 'Note: If AIDE is not installed, this finding is not applicable.

Verify Advanced Intrusion Detection Environment (AIDE) is configured on the system by performing a manual check:

$ sudo aide -c /etc/aide/aide.conf --check

Example output:
...
Start timestamp: 2024-10-30 14:22:38 -0400 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!
...

If AIDE is being used for system file integrity checking and the command fails, this is a finding.'
  desc 'fix', 'Initialize the AIDE package (this may take a few minutes):
$ sudo aideinit
Running aide --init...

The new database will need to be renamed to be read by AIDE:
$ sudo cp -p /var/lib/aide/aide.db.new /var/lib/aide/aide.db

Perform a manual check:
$ sudo aide -c /etc/aide/aide.conf --check

Example output:
...
Start timestamp: 2024-10-30 14:22:38 -0400 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!
...

Done.'
  impact 0.5
  tag check_id: 'C-74683r1066437_chk'
  tag severity: 'medium'
  tag gid: 'V-270650'
  tag rid: 'SV-270650r1066439_rule'
  tag stig_id: 'UBTU-24-100110'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-74584r1066438_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  only_if('Skipping as AIDE is not installed so control not applicable.', impact: 0.0) do
    package('aide').installed?
  end

  describe 'Manual verification is needed' do
    skip 'Manual verification is needed'
  end
end
