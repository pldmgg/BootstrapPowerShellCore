[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:DownloadNugetPackage}.Ast.Extent.Text
    ${Function:GetArchScripts}.Ast.Extent.Text
    ${Function:GetCentOS7Scripts}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetDebian8Scripts}.Ast.Extent.Text
    ${Function:GetDebian9Scripts}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetDomainName}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetFedoraScripts}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetMacOSScripts}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetOpenSUSE423Scripts}.Ast.Extent.Text
    ${Function:GetRaspbianScripts}.Ast.Extent.Text
    ${Function:GetUbuntu1404Scripts}.Ast.Extent.Text
    ${Function:GetUbuntu1604Scripts}.Ast.Extent.Text
    ${Function:GetUbuntu1804Scripts}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetWindowsScripts}.Ast.Extent.Text
    ${Function:InstallLinuxPackage}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:SSHScriptBuilder}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:Bootstrap-PowerShellCore}.Ast.Extent.Text
    ${Function:Get-SSHProbe}.Ast.Extent.Text
    ${Function:Get-SudoStatus}.Ast.Extent.Text
    ${Function:Remove-SudoPwd}.Ast.Extent.Text
)


# From: https://gist.github.com/skyl/36563a5be809e54dc139
$MacBrewInstallNoSudo = @'
#!/System/Library/Frameworks/Ruby.framework/Versions/Current/usr/bin/ruby

argsarray = ARGV

# SET YOUR_HOME TO THE ABSOLUTE PATH OF YOUR HOME DIRECTORY
# chmod +x install.rb
# ./install.rb
YOUR_HOME = "#{ARGV[0]}"

HOMEBREW_PREFIX = "#{YOUR_HOME}/usr/local"
HOMEBREW_CACHE = '/Library/Caches/Homebrew'
HOMEBREW_REPO = 'https://github.com/Homebrew/homebrew'

module Tty extend self
  def blue; bold 34; end
  def white; bold 39; end
  def red; underline 31; end
  def reset; escape 0; end
  def bold n; escape "1;#{n}" end
  def underline n; escape "4;#{n}" end
  def escape n; "\033[#{n}m" if STDOUT.tty? end
end

class Array
  def shell_s
    cp = dup
    first = cp.shift
    cp.map{ |arg| arg.gsub " ", "\\ " }.unshift(first) * " "
  end
end

def ohai *args
  puts "#{Tty.blue}==>#{Tty.white} #{args.shell_s}#{Tty.reset}"
end

def warn warning
  puts "#{Tty.red}Warning#{Tty.reset}: #{warning.chomp}"
end

def system *args
  abort "Failed during: #{args.shell_s}" unless Kernel.system(*args)
end

def sudo *args
  #ohai "/usr/bin/sudo", *args
  #system "/usr/bin/sudo", *args
  system *args
end

def getc  # NOTE only tested on OS X
  system "/bin/stty raw -echo"
  if STDIN.respond_to?(:getbyte)
    STDIN.getbyte
  else
    STDIN.getc
  end
ensure
  system "/bin/stty -raw echo"
end

def wait_for_user
  puts
  puts "Press RETURN to continue or any other key to abort"
  c = getc
  # we test for \r and \n because some stuff does \r instead
  abort unless c == 13 or c == 10
end

module Version
  def <=>(other)
    split(".").map { |i| i.to_i } <=> other.split(".").map { |i| i.to_i }
  end
end

def macos_version
  @macos_version ||= `/usr/bin/sw_vers -productVersion`.chomp[/10\.\d+/].extend(Version)
end

def git
  @git ||= if ENV['GIT'] and File.executable? ENV['GIT']
    ENV['GIT']
  elsif Kernel.system '/usr/bin/which -s git'
    'git'
  else
    exe = `xcrun -find git 2>/dev/null`.chomp
    exe if $? && $?.success? && !exe.empty? && File.executable?(exe)
  end

  return unless @git
  # Github only supports HTTPS fetches on 1.7.10 or later:
  # https://help.github.com/articles/https-cloning-errors
  `#{@git} --version` =~ /git version (\d\.\d+\.\d+)/
  return if $1.nil? or $1.extend(Version) < "1.7.10"

  @git
end

def chmod?(d)
  File.directory?(d) && !(File.readable?(d) && File.writable?(d) && File.executable?(d))
end

def chgrp?(d)
  !File.grpowned?(d)
end

# Invalidate sudo timestamp before exiting
#at_exit { Kernel.system "/usr/bin/sudo", "-k" }

# The block form of Dir.chdir fails later if Dir.CWD doesn't exist which I
# guess is fair enough. Also sudo prints a warning message for no good reason
Dir.chdir "#{YOUR_HOME}/usr"

####################################################################### script
abort "See Linuxbrew: http://brew.sh/linuxbrew/" if /linux/i === RUBY_PLATFORM
abort "MacOS too old, see: https://github.com/mistydemeo/tigerbrew" if macos_version < "10.5"
abort "Don't run this as root!" if Process.uid == 0
#abort <<-EOABORT unless `groups`.split.include? "admin"
#This script requires the user #{ENV['USER']} to be an Administrator. If this
#sucks for you then you can install Homebrew in your home directory or however
#you please; please refer to our homepage. If you still want to use this script
#set your user to be an Administrator in System Preferences or `su' to a
#non-root user with Administrator privileges.
#EOABORT
abort <<-EOABORT unless Dir["#{HOMEBREW_PREFIX}/.git/*"].empty?
It appears Homebrew is already installed. If your intent is to reinstall you
should do the following before running this installer again:
    rm -rf #{HOMEBREW_PREFIX}/Cellar #{HOMEBREW_PREFIX}/.git && brew cleanup
EOABORT
# Tests will fail if the prefix exists, but we don't have execution
# permissions. Abort in this case.
abort <<-EOABORT if File.directory? HOMEBREW_PREFIX and not File.executable? HOMEBREW_PREFIX
The Homebrew prefix, #{HOMEBREW_PREFIX}, exists but is not searchable. If this is
not intentional, please restore the default permissions and try running the
installer again:
    sudo chmod 775 #{HOMEBREW_PREFIX}
EOABORT
abort <<-EOABORT if `/usr/bin/xcrun clang 2>&1` =~ /license/ && !$?.success?
You have not agreed to the Xcode license.
Before running the installer again please agree to the license by opening
Xcode.app or running:
    sudo xcodebuild -license
EOABORT

ohai "This script will install:"
puts "#{HOMEBREW_PREFIX}/bin/brew"
puts "#{HOMEBREW_PREFIX}/Library/..."
puts "#{HOMEBREW_PREFIX}/share/man/man1/brew.1"

chmods = %w( . bin etc include lib lib/pkgconfig Library sbin share var var/log share/locale share/man
             share/man/man1 share/man/man2 share/man/man3 share/man/man4
             share/man/man5 share/man/man6 share/man/man7 share/man/man8
             share/info share/doc share/aclocal ).
             map { |d| File.join(HOMEBREW_PREFIX, d) }.select { |d| chmod?(d) }
chgrps = chmods.select { |d| chgrp?(d) }

unless chmods.empty?
  ohai "The following directories will be made group writable:"
  puts(*chmods)
end
unless chgrps.empty?
  ohai "The following directories will have their group set to #{Tty.underline 39}admin#{Tty.reset}:"
  puts(*chgrps)
end

wait_for_user if STDIN.tty?

if File.directory? HOMEBREW_PREFIX
  sudo "/bin/chmod", "g+rwx", *chmods unless chmods.empty?
  sudo "/usr/bin/chgrp", "admin", *chgrps unless chgrps.empty?
else
  sudo "/bin/mkdir", HOMEBREW_PREFIX
  sudo "/bin/chmod", "g+rwx", HOMEBREW_PREFIX
  # the group is set to wheel by default for some reason
  sudo "/usr/bin/chgrp", "admin", HOMEBREW_PREFIX
end

sudo "/bin/mkdir", HOMEBREW_CACHE unless File.directory? HOMEBREW_CACHE
sudo "/bin/chmod", "g+rwx", HOMEBREW_CACHE if chmod? HOMEBREW_CACHE

if macos_version >= "10.9"
  developer_dir = `/usr/bin/xcode-select -print-path 2>/dev/null`.chomp
  if developer_dir.empty? || !File.exist?("#{developer_dir}/usr/bin/git")
    ohai "Installing the Command Line Tools (expect a GUI popup):"
    sudo "/usr/bin/xcode-select", "--install"
    puts "Press any key when the installation has completed."
    getc
  end
end

ohai "Downloading and installing Homebrew..."
Dir.chdir HOMEBREW_PREFIX do
  if git
    # we do it in four steps to avoid merge errors when reinstalling
    system git, "init", "-q"

    # "git remote add" will fail if the remote is defined in the global config
    system git, "config", "remote.origin.url", HOMEBREW_REPO
    system git, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"

    args = git, "fetch", "origin", "master:refs/remotes/origin/master", "-n"
    args << "--depth=1" if ARGV.include? "--fast"
    system(*args)

    system git, "reset", "--hard", "origin/master"
  else
    # -m to stop tar erroring out if it can't modify the mtime for root owned directories
    # pipefail to cause the exit status from curl to propogate if it fails
    # we use -k for curl because Leopard has a bunch of bad SSL certificates
    curl_flags = "fsSL"
    curl_flags << "k" if macos_version <= "10.5"
    system "/bin/bash -o pipefail -c '/usr/bin/curl -#{curl_flags} #{HOMEBREW_REPO}/tarball/master | /usr/bin/tar xz -m --strip 1'"
  end
end

warn "#{HOMEBREW_PREFIX}/bin is not in your PATH." unless ENV['PATH'].split(':').include? "#{HOMEBREW_PREFIX}/bin"

ohai "Installation successful!"
ohai "Next steps"

if macos_version < "10.9" and macos_version > "10.6"
  `/usr/bin/cc --version 2> /dev/null` =~ %r[clang-(\d{2,})]
  version = $1.to_i
  puts "Install the #{Tty.white}Command Line Tools for Xcode#{Tty.reset}: https://developer.apple.com/downloads" if version < 425
else
  puts "Install #{Tty.white}Xcode#{Tty.reset}: https://developer.apple.com/xcode" unless File.exist? "/usr/bin/cc"
end

puts "Run `brew doctor` #{Tty.white}before#{Tty.reset} you install anything"
puts "Run `brew help` to get started"
'@

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/UUl1Nrd/NJ9xFVyugJhJfRS
# bnagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFI/0YY7t8Yytru26
# pNKcJVNfNsE6MA0GCSqGSIb3DQEBAQUABIIBAA2zdWnhPTyugICpWxIk9M4PFhAl
# 0nM3K1+Jq2aKKLZKnJRXyFvAtuklVYfOqvscdYHywp3A4Q0aSeFneIFbaDDza2QQ
# yH6sgEoEiUN1ppLsqTWm4srT+xoyWu8zE9mhZT2Flg3uoXFuA5ZIdQ06G4PJOlfC
# MCqEG4Do8w1G4SijnKCVyq2DxUetAv5IT+1N88OA8GJOloSH3o7FX9MAxl3asSNN
# YVNxB0qR1K8c/yn2UCutzPxQ7iDwMF87v0m/xyurKhxHeeiO1Dxjs6wkpQ0bs48+
# DIyqyiWP0xFT2/acTsYlLia31525kWRUrFuTh4w4tHY4Og1lm373t5/nZQY=
# SIG # End signature block
