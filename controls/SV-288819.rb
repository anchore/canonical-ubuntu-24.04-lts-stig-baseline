control 'SV-288819' do
  title 'Ubuntu 24.04 LTS must not assign an interactive login shell for system accounts.'
  desc 'Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to use system accounts.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS system accounts do not have an interactive login shell with the following command:

Run the following command to list any system account (UID < 1000) that has an interactive shell, excluding authorized system utility accounts (root, sync, shutdown, halt):

$ awk -F: '(($3 > 0 && $3 < 1000) && $1 !~ /^(halt|sync|shutdown)$/ && $7 !~ /(nologin|false)$/) {print $1 ":" $3 ":" $7}' /etc/passwd

If the command returns any output, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS so that all noninteractive accounts on the system do not have an interactive shell assigned to them.

If the system account needs a shell assigned for mission operations, document the need with the information system security officer (ISSO).

Run the following command to disable the interactive shell for a specific noninteractive user account:

$ sudo usermod -s /usr/sbin/nologin <user>'
  impact 0.5
  tag check_id: 'C-93508r1261503_chk'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-288819'
  tag rid: 'SV-288819r1261505_rule'
  tag stig_id: 'UBTU-24-101100'
  tag fix_id: 'F-93413r1261504_fix'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'
  tag 'container'

  # DISA's check: system accounts (0 < UID < 1000) other than halt, sync and shutdown must have a
  # shell ending in nologin or false.
  exempt_accounts = %w[halt sync shutdown]
  interactive_system_accounts = passwd.where { uid.to_i.positive? && uid.to_i < 1000 && !exempt_accounts.include?(user) && shell.to_s !~ /(nologin|false)$/ }
  offenders = interactive_system_accounts.users.zip(interactive_system_accounts.uids, interactive_system_accounts.shells).map { |entry| entry.join(':') }

  describe 'System accounts (UID 1-999, excluding halt, sync and shutdown)' do
    it 'do not have an interactive login shell' do
      expect(offenders).to be_empty, "System accounts with an interactive shell:\n\t- #{offenders.join("\n\t- ")}"
    end
  end
end
