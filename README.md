# Hyper-V automation
The idea of this project is to speed up the VM deployments. Instead of creating each VM in GUI and set all its properies which can be very time-consuming, we can deploy multiple VM at once with desired configuration. I have chosen to work with JSON files for persistent configuration and for VM inventory.

## Features

- [x] VM Deployment
- [x] Network configuration
- [x] Joining VM to domain
- [x] Roles and features installation and configuration
- [x] Creating Random AD users
- [x] Creating AD users from a CSV file
- [x] Creating Storage Pool with SMB and DFS shares
- [x] Demoting a Domain Controller
- [x] Ability to chose JSON VM Template file

## requirements

*   (IMPORTANT) Powershell 7x and newer.
    * The conversion of .JSON file in Powershell earlier than 7 is different, causing nasty problems.
* .vhdx sysprep images.

The scripts are deploying the VM as differencing disk and the parent disk needs to be present at all time. This can be changed in vm-deployments.ps1 file.

## Post deployment requirements

* credentials.csv (for post deployment, eg network configuration).
Example of credentials.csv is included in this project.

* domain-users.csv (in case adding AD users)

## Installation instructions

### PowerShell 7:
Link to Powershell Download can be found donw blow 
* [PowerShell 7 - Stable release](https://aka.ms/powershell-release?tag=stable)
* [PowerShell 7 - LTS release](https://aka.ms/powershell-release?tag=lts)
* [PowerShell 7 - Preview release](https://aka.ms/powershell-release?tag=preview)

Grab the link below and download to your desired folder location:

    git clone https://github.com/kosmolito/hyperv-automation.git

## Usage

Run the main.ps1 where you can chose either to deploy new VM or cofigure existing VM. 

On the first deployment you will be asked to enter the path for sysprep images. After that the information will be stored config.json file in order to avoid filling the same information over and over again.

This is done for each machine and the script is looking for hostname and in that way differentiating the path of sysprep images and the path where to store the new deployed VM.

# Contributions

Feel free to send pull requests or fill out issues when you encounter them. I'm also open to adding direct maintainers/contributors and working together!