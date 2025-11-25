# Docker VM related code

curl -sL https://raw.githubusercontent.com/codefresh-io/docker-vm/master/docker-init-linux.sh

# Powershell command:

curl https://raw.githubusercontent.com/codefresh-io/docker-vm/master/hybrid/hybrid-windows.ps1 -o hybrid-windows.ps1 

Use flag -use_tempdir_symlink to create symlink instead C:\Windows\SystemTemp linked to targed folder read from DOCKER_TMPDIR environment variable (or default C:\SystemTemp):

__.\hybrid-windows-pr.ps1 -use_tempdir_symlink__
