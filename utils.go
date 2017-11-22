package dockermachinedriverkcps

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/docker/machine/libmachine/log"
	"github.com/uesyn/gokcps"

	"golang.org/x/crypto/ssh"
)

func getServiceOfferingID(cs *gokcps.KCPSClient, offeringname string) (string, error) {
	p := cs.AccountDomain.NewListServiceOfferingsParams()
	p.SetName(offeringname)
	res, err := cs.AccountDomain.ListServiceOfferings(p)
	if err != nil {
		return "", err
	}

	if len(res.ServiceOfferings) == 0 {
		return "", fmt.Errorf("Serviceoffering not found.")
	}

	if len(res.ServiceOfferings) > 1 {
		return "", fmt.Errorf("Too many Serviceofferings are matched.")
	}

	return res.ServiceOfferings[0].Id, nil
}

func getTemplateID(cs *gokcps.KCPSClient, templatename string) (string, error) {
	p := cs.Template.NewListTemplatesParams("self")
	p.SetName(templatename)
	resp, err := cs.Template.ListTemplates(p)
	if err != nil {
		return "", nil
	}
	if len(resp.Templates) != 1 {
		return "", errors.New("Template not found")
	}
	return resp.Templates[0].Id, nil
}

func getZoneID(cs *gokcps.KCPSClient, zonename string) (string, error) {
	p := cs.AccountDomain.NewListZonesParams()
	p.SetName(zonename)
	resp, err := cs.AccountDomain.ListZones(p)
	if err != nil {
		return "", err
	}

	if resp.Count != 1 {
		return "", errors.New("Zone not found")
	}

	return resp.Zones[0].Id, nil
}

func getPublicIpID(cs *gokcps.KCPSClient, publicip string) (string, error) {
	p := cs.Nic.NewListPublicIpAddressesParams()
	p.SetIpaddress(publicip)
	resp, err := cs.Nic.ListPublicIpAddresses(p)
	if err != nil {
		return "", err
	}

	if resp.Count != 1 {
		return "", fmt.Errorf("Public IP not found.")
	}
	return resp.PublicIpAddresses[0].Id, nil
}

func getNetworkID(cs *gokcps.KCPSClient, networkname string) (string, error) {
	p := cs.AccountDomain.NewListNetworksParams()
	p.SetKeyword(networkname)
	resp, err := cs.AccountDomain.ListNetworks(p)
	if err != nil {
		return "", err
	}

	if resp.Count != 1 {
		return "", fmt.Errorf("Network not found.")
	}
	return resp.Networks[0].Id, nil
}

func injectSSHPubKey(ip, user, port, pass, keypath string) error {
	log.Info("Injecting ssh pubkey...")
	buf, err := ioutil.ReadFile(keypath)
	if err != nil {
		return err
	}
	keystring := string(buf)
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	var client *ssh.Client
	log.Info("SSH Connection IP  : " + ip)
	log.Info("SSH Connection Port: " + port)
	for i := 0; i < 10; i++ {
		log.Info("connection trying... ", i)
		client, err = ssh.Dial("tcp", ip+":"+port, config)
		if err != nil {
			log.Info(err)
			time.Sleep(3 * time.Second)
		} else {
			break
		}
	}
	defer client.Close()

	commands := []string{
		"if [ ! -e ${HOME}/.ssh ]; then mkdir ${HOME}/.ssh; fi",
		"chmod 700 ${HOME}/.ssh",
		"echo \"" + keystring + "\" >> ${HOME}/.ssh/authorized_keys",
		"chmod 600 ${HOME}/.ssh/authorized_keys",
	}
	_, err = sshRunCommands(client, commands)

	if err != nil {
		return err
	}

	sshdconfcommands := []string{
		"sudo sed -ie \"s/.*PasswordAuthentication.*//g\" /etc/ssh/sshd_config",
		"sudo sh -c \"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config\"",
		"sudo systemctl restart sshd",
	}
	_, _ = sshRunCommands(client, sshdconfcommands)

	return nil
}

func sshRunCommands(sshclient *ssh.Client, commands []string) (string, error) {
	var b bytes.Buffer
	for _, c := range commands {
		session, err := sshclient.NewSession()
		session.Stdout = &b
		if err != nil {
			return "", err
		}
		defer session.Close()
		if err := session.Run(c); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func waitForSSHPortOpen(host string, port int) error {
	done := make(chan struct{}, 1)
	cancel := make(chan struct{}, 1)
	go func() {
	L:
		for {
			p := NewPortScanner(host, port, 5*time.Second)
			if p.IsOpen() {
				done <- struct{}{}
				log.Info("SSH Port has Opened.")
				break L
			}
			select {
			case <-cancel:
				log.Info("SSH scan was canceled.")
				break L
			default:
				time.Sleep(7 * time.Second)
			}
		}
	}()
	select {
	case <-done:
		cancel <- struct{}{}
		log.Info("SSH Port scan has done.")
		return nil
	case <-time.After(300 * time.Second):
		cancel <- struct{}{}
		log.Info("SSH Port scan timeout.")
		return fmt.Errorf("SSH Port scan timeout.")
	}
}
