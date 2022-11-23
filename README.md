# Hyper-V automation
The idea of this project is to speed up the VM deployments. Instead of creating each VM in GUI and set all its properies which can be very time-consuming, we can deploy multiple VM at once with desired configuration. I have chosen to work with JSON files for persistent configuration and for VM inventory.

## Features

- [x] VM Deployment
- [x] Network configuration
- [x] Roles and features installation and configuration

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

Grab the link below and download to your desired folder location:

    git clone https://github.com/kosmolito/hyperv-automation.git

## Usage

Run the main.ps1 where you can chose either to deploy new VM or cofigure existing VM. 

On the first deployment you will be asked to enter the path for sysprep images. After that the information will be stored menu.json file in order to avoid filling the same information over and over again.

This is done for each machine and the script is looking for hostname and in that way differentiating the path of sysprep images and the path where to store the new deployed VM.

# Contributions

Feel free to send pull requests or fill out issues when you encounter them. I'm also open to adding direct maintainers/contributors and working together!

# Future plans

- [x] Deploying labs with desired amount of VM and roles


