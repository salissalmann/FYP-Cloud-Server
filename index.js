// Server
const express = require('express');
const app = express();
const { exec } = require('child_process');

const sshKeyFilename = 'terraform-key';
//Json parser
app.use(express.json());

//allow cors
const cors = require('cors');
app.use(cors(
    {
        origin: 'http://127.0.0.1:3000',
    }
));



// Routes
// API TO GENERATE SSH KEYS IN NODEJS WITH NAME "terraform-key"
app.post('/generate-ssh-key', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        console.log(ProviderName);
        if (!ProviderName) {
            res.status(500).send({error: 'Error generating SSH key' , success: false} );
            return;
        }

        const command = `mkdir -p ${ProviderName} && ssh-keygen -t rsa -b 4096 -f ./${ProviderName}/${sshKeyFilename} -q -N ""`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating SSH key: ${error}`);
                res.status(500).send({error: 'Error generating SSH key' , success: false});
                return;
            }
        });

        setTimeout(() => {
            res.status(200).send({message: 'SSH key generated successfully' , success: true});
        }, 1000);

    } catch (error) {
        res.status(500).send({error: 'Error generating SSH key' , success: false});
    }
});

app.post('/generate-aws-provider-file', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const AccessKey = req.body.AccessKey;
        const SecretKey = req.body.SecretKey;

        if (!ProviderName) {
            console.error(`Error generating AWS provider file: ProviderName is required`);
            res.status(500).send({error: 'Error generating AWS provider file' , success: false});
            return;
        }

        const command = `mkdir -p ${ProviderName} && echo 'provider \"aws" {\n region = var.REGION\n access_key = "${AccessKey}"\n secret_key = "${SecretKey}"\n }' > ./${ProviderName}/provider.tf`;
        exec(command , (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS provider file: ${error}`);
                res.status(500).send({error: 'Error generating AWS provider file' , success: false , description: error});
            } 
        })

        setTimeout(() => {
            res.status(200).send({message: 'AWS provider file generated successfully' , success: true , description: 'AWS provider file generated successfully'});
        }, 1500);

    } catch (error) {
        res.status(500).send({error: 'Error generating AWS provider file' , success: false , description: error});
    }
})

app.post('/generate-instance-provisioningfile', (req, res) => {
    try {
        const ProviderName = req.body.ProviderName;
        const VPC_Generation = `mkdir -p ${ProviderName} && echo 'resource "aws_default_vpc" "default" {\n\ttags = {\n\t\tName = "Default VPC"\n\t}\n }' > ./${ProviderName}/instance.tf`;

        exec(VPC_Generation, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS instance provisioning file: ${error}`);
                res.status(500).send('Error generating AWS instance provisioning file');
                return;
            }
        });

        const InBoundTobeAllowed = [22, 80, 443]

        let Commands = `'\nresource "aws_security_group" "allow_tls" {\n\tname        = "allow_tls"\n\tdescription = "Allow TLS inbound traffic"\n\tvpc_id      = aws_default_vpc.default.id\n\t\n\t`;
        for (let i = 0; i < InBoundTobeAllowed.length; i++) {
            Commands += `ingress {\n\t\tdescription = "TLS from VPC"\n\t\tfrom_port   = ${InBoundTobeAllowed[i]}\n\t\tto_port     = ${InBoundTobeAllowed[i]}\n\t\tprotocol    = "tcp"\n\t\tcidr_blocks = ["0.0.0.0/0"] \n\t\tipv6_cidr_blocks = ["::/0"]\n\t}\n\t`;
        }

        Commands += `egress {\n\t\tdescription = "TLS from VPC"\n\t\tfrom_port   = 0\n\t\tto_port     = 0\n\t\tprotocol    = "-1"\n\t\tcidr_blocks = ["0.0.0.0/0"] \n\t\tipv6_cidr_blocks = ["::/0"]\n\t}\n}'`;
        const SecurityGroupGeneration = `mkdir -p ${ProviderName} && echo ${Commands} >> ./${ProviderName}/instance.tf`;
        exec(SecurityGroupGeneration, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error generating AWS instance provisioning file: ${error}`);
                res.status(500).send('Error generating AWS instance provisioning file');
                return;
            }
        })


        const command = `mkdir -p ${ProviderName} && echo 'resource "aws_key_pair" "terraform_key" {\n\tkey_name   = "terraform-key"\n\tpublic_key = file("terraform-key.pub")\n}\n\nresource "aws_instance" "terraform_with_key" {\n\tami           = var.AMIs[var.REGION]\n\tinstance_type = "t2.micro"\n\tkey_name      = aws_key_pair.terraform_key.key_name\n\ttags = {\n\t\tName = "terraform_ec2"\n\t}\n\tvpc_security_group_ids = [aws_security_group.allow_tls.id]\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error({ error: `Error generating AWS instance provisioning file: ${error}`, success: false });
                return;
            }
        }
        );

        setTimeout(() => {
            res.status(200).send({ message: 'AWS instance provisioning file generated successfully', success: true });
        } , 2000);
    } catch (error) {
        res.status(500).send({ error: 'Error generating AWS instance provisioning file', success: false });
    }
})


app.post('/terraform-init', (req, res) => {
    try {
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform init`;

        const childProcess = exec(command);

        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                console.log('Terraform init executed successfully');
                res.status(200).send('Terraform init executed successfully');
            } else {
                console.error(`Error executing terraform init. Exit code: ${code}`);
                res.status(500).send(`Error executing terraform init. Exit code: ${code}`);
            }
        });
    } catch (error) {
        console.error(`Error executing terraform init: ${error}`);
        res.status(500).send('Error executing terraform init');
    }
});

const ModifyLogs = (logs) => {
    logs = logs.split('\n');
    let jsonLogs = "";
    for (const line of logs) {
        let cleanLine = line.replace(/\[\d+m/g, '').trim();
        //remove unnecessary characters
        cleanLine = cleanLine.replace(//g, '');
        cleanLine = cleanLine.replace(/\[0K/g, '');
        cleanLine = cleanLine.replace(/\[0m/g, '');
        jsonLogs += cleanLine + '\n';
    }
    return jsonLogs;
}


app.post('/terraform-plan', (req, res) => {
    try {
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform plan -out=tfplan`;

        const childProcess = exec(command);
        let logs = '';
        childProcess.stdout.on('data', (data) => {
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({message: 'Terraform plan executed successfully' , success: true , description: jsonLogs});
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({error: `Error executing terraform plan. Exit code: ${code}` , success: false , description: jsonLogs});
            }
        });
    } catch (error) {
        res.status(500).send({error: 'Error executing terraform plan' , success: false , description: error});
    }
})

app.post('/terraform-apply', (req, res) => {
    try{
        const providerName = req.body.ProviderName;
        const command = `cd ${providerName} && terraform apply --auto-approve`;

        const childProcess = exec(command);

        let logs = '';
        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {                
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({message: 'Terraform apply executed successfully' , success: true , description: jsonLogs});
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({error: `Error executing terraform apply. Exit code: ${code}` , success: false , description: jsonLogs});
            }
        });
    }
    catch(error){
        res.status(500).send({error: 'Error executing terraform apply' , success: false , description: error});
    }
})



const axios = require('axios');

app.get('/users/getGithubAccessToken', async (req, res) => {
    try {
        console.log("helloo")
        const code = req.query.code;
        const CLIENT_ID = "b55016a7680d8e89d8ba";
        const CLIENT_SECRET = "dc04965d92d7328ac45ee9d07ca28aa9a6dc6d8a"
        const response = await axios({
            method: 'post',
            url: `https://github.com/login/oauth/access_token?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&code=${code}`,
            headers: {
                accept: 'application/json'
            }
        });
        const data = await response.data;
        console.log(data);
        const accessToken = data.access_token;
        res.status(200).json({ data: accessToken });
    } catch (error) {
        console.error(`Error getting access token: ${error}`);
        res.status(500).send('Error getting access token');
    }
})


app.post('/users/getGithubUserData', async (req, res) => {
    try {
        //access token from header
        const accessToken = req.headers.authorization.split(' ')[1];
        console.log(accessToken);
        const response = await axios({
            method: 'get',
            url: `https://api.github.com/user`,
            headers: {
                Authorization: `token ${accessToken}`
            }
        });
        const data = await response.data;
        res.status(200).json({ data: data });        
    } catch (error) {
        console.error(`Error getting user data: ${error}`);
        res.status(500).send('Error getting user data');
    }
})


app.post('/users/getUserRepos', async (req, res) => {
    try {
        //access token from header
        const accessToken = req.headers.authorization.split(' ')[1];
        console.log(accessToken);
        const response = await axios({
            method: 'get',
            url: `https://api.github.com/user/repos`,
            headers: {
                Authorization: `token ${accessToken}`
            }
        });
        const data = await response.data;
        res.status(200).json({ data: data });        
    } catch (error) {
        console.error(`Error getting user data: ${error}`);
        res.status(500).send('Error getting user data');        
    }
})

const fs = require('fs');

//Send SSH key, provider.tf and instance.tf to frontend
app.post('/users/getAWSFiles', async (req, res) => { 
    try {
        const ProviderName = req.body.ProviderName;
        const sshKey = await fs.readFileSync(`./${ProviderName}/${sshKeyFilename}`, 'utf8');
        const providerFile = await fs.readFileSync(`./${ProviderName}/provider.tf`, 'utf8');
        const instanceFile = await fs.readFileSync(`./${ProviderName}/instance.tf`, 'utf8');

        const terraformState = await fs.readFileSync(`./${ProviderName}/terraform.tfstate`);
        const terraformStateJson = JSON.parse(terraformState);
        const instancePublicIP = terraformStateJson.resources[1].instances[0].attributes.public_ip;
        const instancePrivateIP = terraformStateJson.resources[1].instances[0].attributes.private_ip;
        const instanceName = terraformStateJson.resources[1].instances[0].attributes.tags.Name;
        const instanceVPC = terraformStateJson.resources[1].instances[0].attributes.vpc_security_group_ids[0];
        const instanceSecurityGroup = terraformStateJson.resources[2].instances[0].attributes.id;

        res.status(200).json({sshKey: sshKey , providerFile: providerFile , instanceFile: instanceFile , instancePublicIP: instancePublicIP , instancePrivateIP: instancePrivateIP , instanceName: instanceName , instanceVPC: instanceVPC , instanceSecurityGroup: instanceSecurityGroup});       
     } catch (error) {
        console.error(`Error zipping AWS files: ${error}`);
        res.status(500).send('Error zipping AWS files');
    }
})


//Generate instance.tf file for Digital Ocean
app.post('/generate-digitalocean-provisioning-file', (req, res) => {
    try{
        const ProviderName = req.body.ProviderName;
        const command = `mkdir -p ${ProviderName} && echo 'terraform {\n\trequired_providers {\n\t\tdigitalocean = {\n\t\t\tsource  = "digitalocean/digitalocean"\n\t\t\tversion = "~> 2.0"\n\t\t}\n\t}\n}' > ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Digital Ocean instance provisioning file generated successfully' , success: true });
                }, 1200);
            }
        })
    }
    catch(error){
        res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
    }
})

app.post('/configure-digitalocean-provider-file', (req, res) => {
    try{
        const token = req.body.token;
        const ProviderName = req.body.ProviderName;

        const command = `mkdir -p ${ProviderName} && echo 'provider "digitalocean" {\n\ttoken = "${token}"\n}' >> ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error configuring Digital Ocean provider file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Digital Ocean provider file configured successfully' , success: true });
                }, 1300);
            }
        })
    }
    catch(error){
        res.status(500).send({error: 'Error configuring Digital Ocean provider file' , success: false , description: error});
    }
})

app.post('/addsshkey-digitalocean-instance-provisioning-file', (req, res) => {
    try{
        console.log(req.body);
        const ProviderName = req.body.ProviderName;
        const monitoring = req.body.monitoring;
        const backups = req.body.backups;

        const command = `mkdir -p ${ProviderName} && echo 'resource "digitalocean_ssh_key" "default" {\n\tname       = "Terraform"\n\tpublic_key = file("./terraform-key.pub")\n}\n\nresource "digitalocean_droplet" "cloudFusionMachine" {\n\timage  = "ubuntu-20-04-x64"\n\tname   = "cloudFusionMachine"\n\tregion = "nyc1"\n\tsize   = "s-1vcpu-1gb"\n\ttags = ["terraform"]\n\tssh_keys = [digitalocean_ssh_key.default.fingerprint]\n\tmonitoring = ${monitoring}\n\tbackups    = ${backups}\n\tipv6       = true\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Digital Ocean instance provisioning file generated successfully' , success: true });
                }, 1400);
            }
        })      
    }
    catch(error){
        res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
    }
})

app.post('/volumes-digitalocean-instance-provisioning-file', (req, res) => {
    try{
        const ProviderName = req.body.ProviderName;
        console.log("ssasas")

        const command = `mkdir -p ${ProviderName} && echo 'resource "digitalocean_volume" "volume" {\n\tname      = "example-volume"\n\tsize      = 10\n\tregion    = "nyc1"\n}\n\nresource "digitalocean_volume_attachment" "volume_attachment" {\n\tdroplet_id = digitalocean_droplet.cloudFusionMachine.id\n\tvolume_id  = digitalocean_volume.volume.id\n}' >> ./${ProviderName}/instance.tf`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Digital Ocean instance provisioning file generated successfully' , success: true });
                } , 1500);
            }
        })      
    }
    catch(error){
        res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
    }
})

app.post('/addoutputs-digitalocean-instance-provisioning-file', (req, res) => {
    try{
        const ProviderName = req.body.ProviderName;
        const command = `mkdir -p ${ProviderName} && echo 'output "droplet_ip" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv4_address\n}\n\noutput "droplet_ip_v6" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv6_address\n}\n\noutput "droplet_private_ip" {\n\tvalue = digitalocean_droplet.cloudFusionMachine.ipv4_address_private\n}' >> ./${ProviderName}/instance.tf`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Digital Ocean instance provisioning file generated successfully' , success: true });
                }, 1600);
            }
        })

    }
    catch(error){
        res.status(500).send({error: 'Error generating Digital Ocean instance provisioning file' , success: false , description: error});
    }
})

app.post('/get-terraform-data', (req, res) => {
    try{
        //get outputs
        const ProviderName = req.body.ProviderName;
        const terraformState = fs.readFileSync(`./${ProviderName}/terraform.tfstate`);
        const terraformStateJson = JSON.parse(terraformState);
        const instancePublicIP = terraformStateJson.outputs.droplet_ip.value;
        const instancePrivateIP = terraformStateJson.outputs.droplet_private_ip.value;
        const instanceIpv6 = terraformStateJson.outputs.droplet_ip_v6.value;

        //get provider.tf
        const sshKey = fs.readFileSync(`./${ProviderName}/${sshKeyFilename}`, 'utf8');
        const providerFile = fs.readFileSync(`./${ProviderName}/instance.tf`, 'utf8');

        res.status(200).json({sshKey: sshKey , providerFile: providerFile , instancePublicIP: instancePublicIP , instancePrivateIP: instancePrivateIP , instanceIpv6: instanceIpv6});
    }
    catch(error){
        res.status(500).send({error: 'Error getting terraform data' , success: false , description: error});
    }
})

app.post('/ansible-config', (req, res) => {
    try{
        console.log(req.body)
        const ProviderName = req.body.ProviderName;
        const public_ip = req.body.instancePublicIP;
        const user = req.body.user;

        //COPY SSH KEY TO ANSIBLE FOLDER
        const command = `mkdir -p Ansible && cp ${ProviderName}/${sshKeyFilename} Ansible/terraform-key.pem`;

        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Ansible inventory file' , success: false , description: error});
                return;
            }
        })


        const command2 = `mkdir -p Ansible && echo 'all:\n  hosts:\n    server:\n      ansible_host: ${public_ip}\n      ansible_user: ${user}\n      ansible_ssh_private_key_file: terraform-key.pem' > Ansible/inventory`;
    
        exec(command2, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Ansible inventory file' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Ansible inventory file generated successfully' , success: true });
                }, 1700);
            }
        })     
    }
    catch(error){
        res.status(500).send({error: 'Error generating Ansible inventory file' , success: false , description: error});
    }
})

app.post('/generate-ansible-playbook', (req, res) => {
    try{
        const ServicesToBeInstalledAndStarted = [
            "nginx",
   /*         "Docker" */
        ]
        const PackagesToBeInstalled = [
                        /*

            "npm",
            "nodejs",
            "git",
            "python3-pip",
            */
        ]


        //Create a file named playbook.yml in ansible folder 
        const command = `mkdir -p Ansible && echo '---\n- hosts: all\n  become: yes\n  tasks:\n    - name: update apt cache\n      apt: update_cache=yes' > Ansible/playbook.yaml`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Ansible playbook' , success: false , description: error});
                return;
            }
        })

        //Install packages
        let Commands = "";
        for (let i = 0; i < PackagesToBeInstalled.length; i++) {
            Commands += `    - name: install ${PackagesToBeInstalled[i]}\n      apt: name=${PackagesToBeInstalled[i]} state=present\n`;
        }

        //Install services
        for (let i = 0; i < ServicesToBeInstalledAndStarted.length; i++) {
            Commands += `    - name: install ${ServicesToBeInstalledAndStarted[i]}\n      apt: name=${ServicesToBeInstalledAndStarted[i]} state=present\n`;
            Commands += `    - name: start ${ServicesToBeInstalledAndStarted[i]}\n      service: name=${ServicesToBeInstalledAndStarted[i]} state=started\n`;
        }

        const command2 = `mkdir -p Ansible && echo '${Commands}' >> Ansible/playbook.yaml`;
        exec(command2, (error, stdout, stderr) => {
            if (error) {
                res.status(500).send({error: 'Error generating Ansible playbook' , success: false , description: error});
                return;
            }
            else{
                setTimeout(() => {
                    res.status(200).send({message: 'Ansible playbook generated successfully' , success: true });
                }, 1800);
            }
        })
    }
    catch(error){
        res.status(500).send({error: 'Error executing Ansible playbook' , success: false , description: error});
    }
})

app.post('/execute-ansible-playbook', (req, res) => {
    try{
        const command = `cd Ansible && chmod 600 terraform-key.pem && export ANSIBLE_HOST_KEY_CHECKING=False && ansible-playbook -i inventory playbook.yaml`;

        const childProcess = exec(command);

        let logs = '';
        childProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`);
            logs += data;
        });

        childProcess.stderr.on('data', (data) => {
            console.error(`stderr: ${data}`);
            logs += data;
        });

        childProcess.on('close', (code) => {
            if (code === 0) {                
                const jsonLogs = ModifyLogs(logs);
                res.status(200).send({message: 'Ansible playbook executed successfully' , success: true , description: jsonLogs});
            } else {
                const jsonLogs = ModifyLogs(logs);
                res.status(500).send({error: `Error executing Ansible playbook. Exit code: ${code}` , success: false , description: jsonLogs});
            }
        });
    }
    catch(error){
        res.status(500).send({error: 'Error executing Ansible playbook' , success: false , description: error});
    }
})






      



          
          




        






app.listen(3001, () => {
    console.log('Server is running on port 3001');
});