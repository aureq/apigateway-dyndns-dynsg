= Introduction =
Perform Dynamic DNS functions using AWS API Gateway and AWS Lambda. Currently, only Route53 and OVH are supported DNS providers.

= Development environment =
Since the Lambda function is run on AWS Lambda, the packaging of this function requires Amazon Linux to prevent symbols errors in Python packages and external libraries.

The code below could be used as `user-data` when launching an EC2 instance.

```bash
#!/bin/bash
sudo yum update -y
sudo yum install git gcc -y
wget http://ohse.de/uwe/releases/lrzsz-0.12.20.tar.gz
tar -xzvf lrzsz-0.12.20.tar.gz
cd lrzsz-0.12.20
./configure --prefix=/usr
make -j2
sudo make install
sudo ln -s /usr/bin/lrz /usr/bin/rz
sudo ln -s /usr/bin/lsz /usr/bin/sz
git clone https://github.com/aureq/apigateway-dyndns-dynsg.git
cd apigateway-dyndns-dynsg
sudo bash bootstrap.sh
sudo update-alternatives --set python /usr/bin/python3.6
virtualenv .env
source .env/bin/activate
pip install .
git remote rm origin
git remote add origin git@github.com:aureq/apigateway-dyndns-dynsg.git
```