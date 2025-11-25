# Docker VM related code

curl -sL https://raw.githubusercontent.com/codefresh-io/docker-vm/master/docker-init-linux.sh

# Powershell command:

curl https://raw.githubusercontent.com/codefresh-io/docker-vm/master/hybrid/hybrid-windows.ps1 -o hybrid-windows.ps1 

Use the -use_tempdir_symlink flag to create a symlink, replacing C:\Windows\SystemTemp with a link to the target folder specified by the DOCKER_TMPDIR environment variable (or defaulting to C:\SystemTemp):

__.\hybrid-windows-pr.ps1 -use_tempdir_symlink__
